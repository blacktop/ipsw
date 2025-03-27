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
	"os"
	"path/filepath"
	"slices"

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

func getHdrsData(hdrs []SegmentHeader) []byte {
	result := new(bytes.Buffer)
	if err := binary.Write(result, binary.LittleEndian, hdrs); err != nil {
		return nil
	}
	return result.Bytes()
}

func getHMACsData(hmacs []HMAC) []byte {
	result := make([]byte, binary.Size(hmacs))
	for i, hmac := range hmacs {
		copy(result[i*32:(i+1)*32], hmac[:])
	}
	return result
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

func encrypt(in string, conf *EncryptConfig) error {
	f, err := os.Open(in)
	if err != nil {
		return err
	}
	defer f.Close()

	finfo, err := f.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file info: %v", err)
	}

	mainSalt, err := generateRandomSalt()
	if err != nil {
		return fmt.Errorf("failed to generate main salt: %v", err)
	}

	mainKey, err := deriveKey(
		conf.SymmetricKey,
		mainSalt[:],
		binary.LittleEndian.AppendUint32(
			[]byte(MainKeyInfo),
			uint32(conf.ProfileID)+(conf.ScryptStrength<<24),
		))
	if err != nil {
		return fmt.Errorf("failed to derive main key: %v", err)
	}

	nextClusterMac, err := generateRandomHMAC()
	if err != nil {
		return fmt.Errorf("failed to generate next cluster HMAC: %v", err)
	}

	clusterSize := segmentSize * segmentsPerCluster
	clusterCount := (finfo.Size() + int64(clusterSize-1)) / int64(clusterSize)
	clustersData := new(bytes.Buffer)

	for i := clusterCount - 1; i >= 0; i-- {
		clusterKey, err := deriveKey(mainKey, []byte{},
			binary.LittleEndian.AppendUint32(
				[]byte(ClusterKeyInfo),
				uint32(i),
			))
		if err != nil {
			return fmt.Errorf("failed to derive cluster key: %v", err)
		}
		var clusterHeaderKey headerKey
		if err := binary.Read(
			hkdf.New(sha256.New, clusterKey, []byte{}, []byte(ClusterKeyMaterialInfo)),
			binary.LittleEndian,
			&clusterHeaderKey,
		); err != nil {
			return fmt.Errorf("failed to derive cluster header key: %v", err)
		}

		data := make([]byte, segmentSize)
		comp := make([]byte, 0, segmentSize)
		segmentHdrs := make([]SegmentHeader, segmentsPerCluster)
		segmentHMACs := make([]HMAC, segmentsPerCluster)
		segmentsData := new(bytes.Buffer)

		for j := range segmentsPerCluster {
			n, ferr := f.ReadAt(data, int64(i*int64(clusterSize)+int64(j*segmentSize)))
			if ferr != nil && ferr != io.EOF {
				return fmt.Errorf("failed to read segment data: %v", ferr)
			}
			if n != 0 && n < segmentSize {
				data = data[:n]
			}
			if n == 0 {
				segmentHdrs[j] = SegmentHeader{
					DecompressedSize: 0,
					CompressedSize:   0,
					Checksum:         [32]byte{},
				}
				segmentHMACs[j], err = generateRandomHMAC()
				if err != nil {
					return fmt.Errorf("failed to generate segment HMAC: %v", err)
				}
			} else {
				switch conf.Compression {
				case LZFSE:
					comp = lzfse.EncodeBuffer(data)
				default:
					return fmt.Errorf("unsupported compression profile: %d", conf.ProfileID)
				}

				if len(comp) >= len(data) {
					comp = data
				}

				segmentHdr := SegmentHeader{
					DecompressedSize: uint32(n),
					CompressedSize:   uint32(len(comp)),
					Checksum:         sha256.Sum256(data),
				}
				segmentHdrs[j] = segmentHdr

				var segmentKey headerKey
				if err := binary.Read(
					hkdf.New(sha256.New, clusterKey, []byte{}, binary.LittleEndian.AppendUint32(
						[]byte(SegmentKeyInfo[:]),
						uint32(j),
					)),
					binary.LittleEndian,
					&segmentKey,
				); err != nil {
					return fmt.Errorf("failed to derive segment key: %v", err)
				}
				encryptedSegment, err := encryptCTR(comp, segmentKey.Key[:], segmentKey.IV[:])
				if err != nil {
					return fmt.Errorf("failed to encrypt segment: %v", err)
				}
				if _, err := segmentsData.Write(encryptedSegment); err != nil {
					return fmt.Errorf("failed to write segment: %v", err)
				}
				segmentHMACs[j], err = getHMAC(segmentKey.MAC[:], encryptedSegment, []byte{})
				if err != nil {
					return fmt.Errorf("failed to write segment HMAC: %v", err)
				}
			}
		}

		encryptedSegmentHdrs, err := encryptCTR(getHdrsData(segmentHdrs), clusterHeaderKey.Key[:], clusterHeaderKey.IV[:])
		if err != nil {
			return fmt.Errorf("failed to encrypt segment: %v", err)
		}

		if _, err := clustersData.Write(encryptedSegmentHdrs); err != nil {
			return fmt.Errorf("failed to write encrypted segment headers: %v", err)
		}
		if _, err := clustersData.Write(nextClusterMac[:]); err != nil {
			return fmt.Errorf("failed to write next cluster HMAC: %v", err)
		}
		if err := binary.Write(clustersData, binary.LittleEndian, segmentHMACs); err != nil {
			return fmt.Errorf("failed to write segment HMACs: %v", err)
		}
		if _, err := clustersData.Write(segmentsData.Bytes()); err != nil {
			return fmt.Errorf("failed to write segments data: %v", err)
		}

		nextClusterMac, err = getHMAC(
			clusterHeaderKey.MAC[:],
			encryptedSegmentHdrs,
			slices.Concat(nextClusterMac[:], getHMACsData(segmentHMACs)), // salt
		)
		if err != nil {
			return fmt.Errorf("failed to write next cluster MAC: %v", err)
		}
	}

	fname := filepath.Join(conf.Output, filepath.Base(in)+".aea")
	if err := os.MkdirAll(filepath.Dir(fname), 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}
	out, err := os.Create(fname)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer out.Close()

	rootHeader := RootHeader{
		FileSize: uint64(finfo.Size()),
		EncyptedSize: uint64(binary.Size(Header{}) +
			len(conf.AuthData) +
			len(mainSalt) +
			binary.Size(encRootHeader{}) +
			clustersData.Len()),
		SegmentSize:        segmentSize,
		SegmentsPerCluster: segmentsPerCluster,
		Compression:        conf.Compression,
		Checksum:           conf.CheckSum,
	}
	var rootHdrKey headerKey
	if err := binary.Read(
		hkdf.New(sha256.New, mainKey, []byte{}, []byte(RootHeaderEncryptedKeyInfo)),
		binary.LittleEndian,
		&rootHdrKey,
	); err != nil {
		return fmt.Errorf("failed to derive root header key: %v", err)
	}
	rootHdrData := new(bytes.Buffer)
	if err := binary.Write(rootHdrData, binary.LittleEndian, rootHeader); err != nil {
		return fmt.Errorf("failed to write root header: %v", err)
	}
	encRootHdr, err := encryptCTR(rootHdrData.Bytes(), rootHdrKey.Key[:], rootHdrKey.IV[:])
	if err != nil {
		return fmt.Errorf("failed to encrypt root header: %v", err)
	}
	rootHdrHMAC, err := getHMAC(rootHdrKey.MAC[:], encRootHdr, slices.Concat(nextClusterMac[:], conf.AuthData))
	if err != nil {
		return fmt.Errorf("failed to get root header HMAC: %v", err)
	}

	// write header
	if err := binary.Write(out, binary.LittleEndian, Header{
		Magic:                    [4]byte{'A', 'E', 'A', '1'},
		ProfileAndScryptStrength: uint32(conf.ProfileID) + (conf.ScryptStrength << 24),
		AuthDataLength:           uint32(len(conf.AuthData)),
	}); err != nil {
		return fmt.Errorf("failed to write AEA header: %v", err)
	}

	// write auth data
	if err := binary.Write(out, binary.LittleEndian, conf.AuthData); err != nil {
		return fmt.Errorf("failed to write auth data: %v", err)
	}

	// TODO: write public key

	// write main salt
	if err := binary.Write(out, binary.LittleEndian, mainSalt); err != nil {
		return fmt.Errorf("failed to write main salt: %v", err)
	}

	// write root header HMAC
	if err := binary.Write(out, binary.LittleEndian, rootHdrHMAC); err != nil {
		return fmt.Errorf("failed to write root header HMAC: %v", err)
	}

	// write encrypted root header
	if _, err := out.Write(encRootHdr); err != nil {
		return fmt.Errorf("failed to write encrypted root header: %v", err)
	}

	// write next cluster HMAC
	if _, err := out.Write(nextClusterMac[:]); err != nil {
		return fmt.Errorf("failed to write next cluster HMAC: %v", err)
	}

	// write clusters data
	if _, err := out.Write(clustersData.Bytes()); err != nil {
		return fmt.Errorf("failed to write clusters data: %v", err)
	}

	log.Infof("Created %s", fname)
	return nil
}

func Encrypt(in string, conf *EncryptConfig) error {
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
	return encrypt(in, conf)
}
