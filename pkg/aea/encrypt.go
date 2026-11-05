package aea

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/lzfse-cgo"
	"golang.org/x/crypto/hkdf"
)

const (
	segmentSize        = 0x100000
	segmentsPerCluster = 256
)

type EncryptConfig struct {
	Output         string
	ProfileID      profileType
	ScryptStrength uint32
	Compression    compressionType
	CheckSum       checksumType
	B64SymKey      string
	SymmetricKey   []byte
	Password       string
	AuthData       []byte
}

func generateRandomSalt() ([32]byte, error) {
	var salt [32]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return [32]byte{}, fmt.Errorf("failed to generate random salt: %v", err)
	}
	return salt, nil
}

func generateRandomHMAC() (HMAC, error) {
	salt, err := generateRandomSalt()
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to generate random HMAC: %v", err)
	}
	return HMAC(salt), nil
}

func encryptCTR(plaintext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create new AES cipher: %v", err)
	}
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCTR(block, iv).XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

func clusterKeyMaterial(mainKey []byte, index uint32) ([]byte, headerKey, error) {
	key, err := deriveKey(mainKey, nil, binary.LittleEndian.AppendUint32([]byte(ClusterKeyInfo), index))
	if err != nil {
		return nil, headerKey{}, fmt.Errorf("failed to derive cluster key: %w", err)
	}
	var material headerKey
	if err := binary.Read(hkdf.New(sha256.New, key, nil, []byte(ClusterKeyMaterialInfo)), binary.LittleEndian, &material); err != nil {
		return nil, headerKey{}, fmt.Errorf("failed to derive cluster header key: %w", err)
	}
	return key, material, nil
}

func encrypt(in string, conf *EncryptConfig) error {
	f, err := os.Open(in)
	if err != nil {
		return err
	}
	defer f.Close()
	finfo, err := f.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file info: %w", err)
	}
	if !finfo.Mode().IsRegular() {
		return fmt.Errorf("input is not a regular file")
	}

	const clusterSize = int64(segmentSize) * segmentsPerCluster
	clusterCount := finfo.Size() / clusterSize
	if finfo.Size()%clusterSize != 0 {
		clusterCount++
	}
	prefixSize := int64(binary.Size(Header{})+32+binary.Size(encRootHeader{})) + int64(len(conf.AuthData))
	segmentHeadersSize := binary.Size(SegmentHeader{}) * segmentsPerCluster
	clusterHeaderSize := int64(segmentHeadersSize + 32 + 32*segmentsPerCluster)
	if clusterCount > 1<<32 || finfo.Size() > math.MaxInt64-prefixSize-clusterCount*clusterHeaderSize {
		return fmt.Errorf("input is too large for an AEA archive")
	}

	mainSalt, err := generateRandomSalt()
	if err != nil {
		return fmt.Errorf("failed to generate main salt: %w", err)
	}
	mainKey, err := deriveKey(conf.SymmetricKey, mainSalt[:], binary.LittleEndian.AppendUint32(
		[]byte(MainKeyInfo), uint32(conf.ProfileID)+(conf.ScryptStrength<<24)))
	if err != nil {
		return fmt.Errorf("failed to derive main key: %w", err)
	}
	nextClusterMac, err := generateRandomHMAC()
	if err != nil {
		return fmt.Errorf("failed to generate next cluster HMAC: %w", err)
	}

	fname := filepath.Join(conf.Output, filepath.Base(in)+".aea")
	if err := os.MkdirAll(filepath.Dir(fname), 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}
	out, err := os.CreateTemp(filepath.Dir(fname), ".ipsw-aea-*")
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer func() {
		out.Close()
		os.Remove(out.Name())
	}()

	data := make([]byte, segmentSize)
	clusterHeader := make([]byte, clusterHeaderSize)
	var segmentHdrs [segmentsPerCluster]SegmentHeader
	var segmentMACs [segmentsPerCluster]HMAC
	var lastClusterOffset int64
	fileSize := prefixSize
	for i := int64(0); i < clusterCount; i++ {
		clusterOffset := fileSize
		fileSize += clusterHeaderSize
		if _, err := out.Seek(fileSize, io.SeekStart); err != nil {
			return fmt.Errorf("failed to reserve cluster header: %w", err)
		}
		clusterKey, clusterHeaderKey, err := clusterKeyMaterial(mainKey, uint32(i))
		if err != nil {
			return err
		}
		clear(segmentHdrs[:])
		for j := range segmentsPerCluster {
			inputOffset := i*clusterSize + int64(j)*segmentSize
			n := min(int64(segmentSize), max(finfo.Size()-inputOffset, 0))
			if n == 0 {
				segmentMACs[j], err = generateRandomHMAC()
				if err != nil {
					return fmt.Errorf("failed to generate segment HMAC: %w", err)
				}
				continue
			}
			plain := data[:n]
			if _, err := f.ReadAt(plain, inputOffset); err != nil {
				return fmt.Errorf("failed to read segment data: %w", err)
			}
			comp := lzfse.EncodeBuffer(plain)
			if len(comp) == 0 || len(comp) >= len(plain) {
				comp = plain
			}
			segmentHdrs[j] = SegmentHeader{
				DecompressedSize: uint32(n),
				CompressedSize:   uint32(len(comp)),
				Checksum:         sha256.Sum256(plain),
			}
			var segmentKey headerKey
			if err := binary.Read(hkdf.New(sha256.New, clusterKey, nil,
				binary.LittleEndian.AppendUint32([]byte(SegmentKeyInfo), uint32(j))),
				binary.LittleEndian, &segmentKey); err != nil {
				return fmt.Errorf("failed to derive segment key: %w", err)
			}
			encryptedSegment, err := encryptCTR(comp, segmentKey.Key[:], segmentKey.IV[:])
			if err != nil {
				return fmt.Errorf("failed to encrypt segment: %w", err)
			}
			if _, err := out.Write(encryptedSegment); err != nil {
				return fmt.Errorf("failed to write segment: %w", err)
			}
			fileSize += int64(len(encryptedSegment))
			segmentMACs[j], err = getHMAC(segmentKey.MAC[:], encryptedSegment, nil)
			if err != nil {
				return fmt.Errorf("failed to get segment HMAC: %w", err)
			}
		}

		if _, err := binary.Encode(clusterHeader[:segmentHeadersSize], binary.LittleEndian, segmentHdrs); err != nil {
			return fmt.Errorf("failed to encode segment headers: %w", err)
		}
		encryptedHeaders, err := encryptCTR(clusterHeader[:segmentHeadersSize], clusterHeaderKey.Key[:], clusterHeaderKey.IV[:])
		if err != nil {
			return fmt.Errorf("failed to encrypt segment headers: %w", err)
		}
		copy(clusterHeader, encryptedHeaders)
		// The reserved next-MAC slot temporarily links to the preceding cluster.
		// The reverse pass replaces every link before publishing the archive.
		clear(clusterHeader[segmentHeadersSize : segmentHeadersSize+32])
		binary.LittleEndian.PutUint64(clusterHeader[segmentHeadersSize:], uint64(lastClusterOffset))
		if _, err := binary.Encode(clusterHeader[segmentHeadersSize+32:], binary.LittleEndian, segmentMACs); err != nil {
			return fmt.Errorf("failed to encode segment HMACs: %w", err)
		}
		if _, err := out.WriteAt(clusterHeader, clusterOffset); err != nil {
			return fmt.Errorf("failed to write cluster header: %w", err)
		}
		lastClusterOffset = clusterOffset
	}

	for i := clusterCount; i > 0; i-- {
		if _, err := out.ReadAt(clusterHeader, lastClusterOffset); err != nil {
			return fmt.Errorf("failed to read cluster header: %w", err)
		}
		previousOffset := int64(binary.LittleEndian.Uint64(clusterHeader[segmentHeadersSize:]))
		copy(clusterHeader[segmentHeadersSize:], nextClusterMac[:])
		_, clusterHeaderKey, err := clusterKeyMaterial(mainKey, uint32(i-1))
		if err != nil {
			return err
		}
		mac, err := getHMAC(clusterHeaderKey.MAC[:], clusterHeader[:segmentHeadersSize], clusterHeader[segmentHeadersSize:])
		if err != nil {
			return fmt.Errorf("failed to get cluster HMAC: %w", err)
		}
		if _, err := out.WriteAt(nextClusterMac[:], lastClusterOffset+int64(segmentHeadersSize)); err != nil {
			return fmt.Errorf("failed to write next cluster HMAC: %w", err)
		}
		nextClusterMac = mac
		lastClusterOffset = previousOffset
	}

	rootHeader := RootHeader{
		FileSize:           uint64(finfo.Size()),
		EncyptedSize:       uint64(fileSize),
		SegmentSize:        segmentSize,
		SegmentsPerCluster: segmentsPerCluster,
		Compression:        conf.Compression,
		Checksum:           conf.CheckSum,
	}
	var rootHdrKey headerKey
	if err := binary.Read(hkdf.New(sha256.New, mainKey, nil, []byte(RootHeaderEncryptedKeyInfo)), binary.LittleEndian, &rootHdrKey); err != nil {
		return fmt.Errorf("failed to derive root header key: %w", err)
	}
	rootHdrData := new(bytes.Buffer)
	if err := binary.Write(rootHdrData, binary.LittleEndian, rootHeader); err != nil {
		return fmt.Errorf("failed to write root header: %w", err)
	}
	encRootHdr, err := encryptCTR(rootHdrData.Bytes(), rootHdrKey.Key[:], rootHdrKey.IV[:])
	if err != nil {
		return fmt.Errorf("failed to encrypt root header: %w", err)
	}
	rootHdrHMAC, err := getRootHeaderHMAC(rootHdrKey.MAC[:], encRootHdr, nextClusterMac, bytes.NewReader(conf.AuthData), uint32(len(conf.AuthData)))
	if err != nil {
		return fmt.Errorf("failed to get root header HMAC: %w", err)
	}
	if _, err := out.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to archive header: %w", err)
	}
	if err := binary.Write(out, binary.LittleEndian, Header{
		Magic:                    [4]byte{'A', 'E', 'A', '1'},
		ProfileAndScryptStrength: uint32(conf.ProfileID) + (conf.ScryptStrength << 24),
		AuthDataLength:           uint32(len(conf.AuthData)),
	}); err != nil {
		return fmt.Errorf("failed to write AEA header: %w", err)
	}
	if _, err := out.Write(conf.AuthData); err != nil {
		return fmt.Errorf("failed to write auth data: %w", err)
	}
	if _, err := out.Write(mainSalt[:]); err != nil {
		return fmt.Errorf("failed to write main salt: %w", err)
	}
	root := encRootHeader{Hmac: rootHdrHMAC, ClusterHmac: nextClusterMac}
	copy(root.Data[:], encRootHdr)
	if err := binary.Write(out, binary.LittleEndian, root); err != nil {
		return fmt.Errorf("failed to write encrypted root header: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("failed to close output file: %w", err)
	}
	if err := os.Rename(out.Name(), fname); err != nil {
		return fmt.Errorf("failed to publish output file: %w", err)
	}
	log.Infof("Created %s", fname)
	return nil
}

func Encrypt(in string, conf *EncryptConfig) error {
	if conf == nil {
		return fmt.Errorf("missing encryption configuration")
	}
	if uint64(len(conf.AuthData)) > math.MaxUint32 {
		return fmt.Errorf("auth data is too large for an AEA archive")
	}
	// set defaults
	conf.ProfileID = SymmetricEncryption
	conf.Compression = LZFSE
	conf.CheckSum = Sha256
	if len(conf.B64SymKey) > 0 {
		key, err := base64.StdEncoding.DecodeString(conf.B64SymKey)
		if err != nil {
			return err
		}
		conf.SymmetricKey = key
	}
	if len(conf.SymmetricKey) != 32 {
		return fmt.Errorf("invalid symmetric key length: %d; expected 32", len(conf.SymmetricKey))
	}
	return encrypt(in, conf)
}
