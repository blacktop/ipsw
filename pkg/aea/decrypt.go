package aea

//go:generate go tool stringer -type=compressionType -output aea_string.go

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/lzfse-cgo"
	"github.com/twmb/murmur3"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/sync/errgroup"
)

const aeaBinPath = "/usr/bin/aea"

const (
	Magic                                = "AEA1"
	MainKeyInfo                          = "AEA_AMK"
	RootHeaderEncryptedKeyInfo           = "AEA_RHEK"
	ClusterKeyInfo                       = "AEA_CK"
	ClusterKeyMaterialInfo               = "AEA_CHEK"
	SegmentKeyInfo                       = "AEA_SK"
	SignatureEncryptionDerivationKeyInfo = "AEA_SEK"
	SignatureEncryptionKeyInfo           = "AEA_SEK2"
	PaddingKeyInfo                       = "AEA_PAK"
)

type profileType uint32

const (
	Signed                     profileType = 0
	SymmetricEncryption        profileType = 1
	SymmetricEncryptionSigned  profileType = 2
	AsymmetricEncryption       profileType = 3
	AsymmetricEncryptionSigned profileType = 4
	PasswordEncryption         profileType = 5
)

type checksumType uint8

const (
	None   checksumType = 0
	Murmur checksumType = 1
	Sha256 checksumType = 2
)

var checksumSize = map[checksumType]uint32{
	None:   0,
	Murmur: 8,
	Sha256: 32,
}

type compressionType uint8

const (
	NONE     compressionType = '-'
	LZ4      compressionType = '4'
	LZBITMAP compressionType = 'b'
	LZFSE    compressionType = 'e'
	LZVN     compressionType = 'f'
	LZMA     compressionType = 'x'
	ZLIB     compressionType = 'z'
)

type Header struct {
	Magic                    [4]byte // AEA1
	ProfileAndScryptStrength uint32
	AuthDataLength           uint32
}

func (h Header) ProfileID() profileType {
	return profileType(h.ProfileAndScryptStrength & 0xffffff)
}
func (h Header) ScryptStrength() uint8 {
	return uint8(h.ProfileAndScryptStrength >> 24)
}
func (h Header) String() string {
	return fmt.Sprintf("magic: %s profile: %d scrypt_strength: %d length: %#x", string(h.Magic[:]), h.ProfileID(), h.ScryptStrength(), h.AuthDataLength)
}

type HMAC [32]byte

type encRootHeader struct {
	Hmac        HMAC
	Data        [48]byte
	ClusterHmac HMAC
}

type RootHeader struct {
	FileSize           uint64
	EncyptedSize       uint64
	SegmentSize        uint32
	SegmentsPerCluster uint32
	Compression        compressionType
	Checksum           checksumType
	_                  [22]byte // padding
}

type headerKey struct {
	MAC HMAC
	Key [32]byte
	IV  [aes.BlockSize]byte
}

type SegmentHeader struct {
	DecompressedSize uint32
	CompressedSize   uint32
	Checksum         [32]byte
}

func decryptCTR(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create new AES cipher: %v", err)
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCTR(block, iv).XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}

func deriveKey(inkey, salt, info []byte) ([]byte, error) {
	key := make([]byte, len(inkey))
	n, err := hkdf.New(sha256.New, inkey, salt, info).Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %v", err)
	}
	if n != len(key) {
		return nil, fmt.Errorf("invalid key length: %d; expected %d", n, len(key))
	}
	return key, nil
}

func getHMAC(key, data, salt []byte) (HMAC, error) {
	mac := hmac.New(sha256.New, key)
	if _, err := mac.Write(slices.Concat(
		salt,
		binary.LittleEndian.AppendUint64(
			data,
			uint64(len(salt)),
		),
	)); err != nil {
		return HMAC{}, fmt.Errorf("failed to write HMAC: %v", err)
	}
	return HMAC(mac.Sum(nil)), nil
}

func decryptClusters(ctx context.Context, r io.ReadSeeker, outfile *os.File, mainKey []byte, clusterMAC HMAC, rootHdr RootHeader) error {
	eg, _ := errgroup.WithContext(ctx)

	segmentHeaderSize := checksumSize[rootHdr.Checksum] + 8
	cindex := uint32(0)
	totalSize := uint64(0)

	for {
		clusterKey, err := deriveKey(mainKey, []byte{},
			binary.LittleEndian.AppendUint32(
				[]byte(ClusterKeyInfo),
				uint32(cindex),
			))
		if err != nil {
			return fmt.Errorf("failed to derive cluster key: %v", err)
		}

		// read segment headers
		var clusterHeaderKey headerKey
		if err := binary.Read(
			hkdf.New(sha256.New, clusterKey, []byte{}, []byte(ClusterKeyMaterialInfo)),
			binary.LittleEndian,
			&clusterHeaderKey,
		); err != nil {
			return fmt.Errorf("failed to derive cluster header key: %v", err)
		}
		encSegmentHdrData := make([]byte, segmentHeaderSize*rootHdr.SegmentsPerCluster)
		if _, err := r.Read(encSegmentHdrData); err != nil {
			return fmt.Errorf("failed to read encrypted segment headers data: %v", err)
		}
		var nextClusterMac HMAC
		if err := binary.Read(r, binary.LittleEndian, &nextClusterMac); err != nil {
			return fmt.Errorf("failed to read next cluster HMAC: %v", err)
		}
		segmentMacData := make([]byte, 32*rootHdr.SegmentsPerCluster)
		if _, err := r.Read(segmentMacData); err != nil {
			return fmt.Errorf("failed to read segment HMAC data: %v", err)
		}
		shmac, err := getHMAC(clusterHeaderKey.MAC[:], encSegmentHdrData, slices.Concat(nextClusterMac[:], segmentMacData))
		if err != nil {
			return fmt.Errorf("failed to get HMAC for encrypted segment headers data: %v", err)
		}
		if !hmac.Equal(clusterMAC[:], shmac[:]) {
			return fmt.Errorf("invalid cluster #%d HMAC: %x; expected %x", cindex, clusterMAC, shmac)
		}
		segmentMACs := make([]HMAC, rootHdr.SegmentsPerCluster)
		if err := binary.Read(bytes.NewReader(segmentMacData), binary.LittleEndian, &segmentMACs); err != nil {
			return fmt.Errorf("failed to read segment HMACs: %v", err)
		}
		segmmentHdrData, err := decryptCTR(encSegmentHdrData, clusterHeaderKey.Key[:], clusterHeaderKey.IV[:])
		if err != nil {
			return fmt.Errorf("failed to decrypt segment headers: %v", err)
		}
		segmentHdrs := make([]SegmentHeader, rootHdr.SegmentsPerCluster)
		if err := binary.Read(bytes.NewReader(segmmentHdrData), binary.LittleEndian, segmentHdrs); err != nil {
			return fmt.Errorf("failed to read segment headers: %v", err)
		}

		// decrypt segments
		for idx, seg := range segmentHdrs {
			if seg.DecompressedSize == 0 {
				continue
			}
			totalSize += uint64(seg.DecompressedSize)
			segmentData := make([]byte, seg.CompressedSize)
			if _, err = r.Read(segmentData); err != nil {
				return fmt.Errorf("failed to read segment data: %v", err)
			}
			decomp := make([]byte, 0, seg.DecompressedSize)
			func(index int, data []byte, size uint32) {
				eg.Go(func() error {
					pos := int64(cindex)*int64(rootHdr.SegmentSize)*int64(rootHdr.SegmentsPerCluster) +
						int64(index)*int64(rootHdr.SegmentSize)
					var segmentKey headerKey
					if err := binary.Read(
						hkdf.New(sha256.New, clusterKey, []byte{}, binary.LittleEndian.AppendUint32(
							[]byte(SegmentKeyInfo[:]),
							uint32(index),
						)),
						binary.LittleEndian,
						&segmentKey,
					); err != nil {
						return fmt.Errorf("failed to derive segment key: %v", err)
					}
					shmac, err := getHMAC(segmentKey.MAC[:], data, []byte{})
					if err != nil {
						return fmt.Errorf("failed to get HMAC for segment header: %v", err)
					}
					if !hmac.Equal(segmentMACs[index][:], shmac[:]) {
						return fmt.Errorf("invalid segment #%d HMAC: %x; expected %x", index, segmentMACs[index], shmac)
					}
					decryptedData, err := decryptCTR(data, segmentKey.Key[:], segmentKey.IV[:])
					if err != nil {
						return fmt.Errorf("failed to decrypt segment data: %v", err)
					}
					if seg.DecompressedSize == seg.CompressedSize { // no compression
						if _, err := outfile.WriteAt(decryptedData, pos); err != nil {
							return fmt.Errorf("failed to write uncompressed decrypted data to file: %v", err)
						}
					} else {
						switch rootHdr.Compression {
						case NONE:
							decomp = decryptedData
						case LZBITMAP:
							lzfse.LzBitMapDecompress(decryptedData, decomp)
						case LZFSE:
							decomp = lzfse.DecodeBuffer(decryptedData)
						case LZMA:
							lzfse.DecodeLZVNBuffer(decryptedData, decomp)
						case ZLIB:
							zr, err := zlib.NewReader(bytes.NewReader(decryptedData))
							if err != nil {
								return fmt.Errorf("failed to create zlib reader: %v", err)
							}
							decomp, err = io.ReadAll(zr)
							if err != nil {
								return fmt.Errorf("failed to read zlib decompressed data: %v", err)
							}
						default:
							// TODO: https://github.com/pierrec/lz4
							// TODO: https://pkg.go.dev/github.com/ulikunitz/xz/lzma
							return fmt.Errorf("unsupported compression type: %s", rootHdr.Compression)
						}
						switch rootHdr.Checksum {
						case None:
						case Sha256:
							if sha256.Sum256(decomp) != seg.Checksum {
								return fmt.Errorf("invalid SHA256 checksum for segment %d (cluster %d): expected %x; got %x", index, cindex, seg.Checksum, sha256.Sum256(decomp))
							}
						case Murmur:
							if murmur3.SeedSum64(0xE2236FDC26A5F6D2, decomp) != binary.LittleEndian.Uint64(seg.Checksum[:8]) {
								return fmt.Errorf("invalid MURMUR checksum for segment %d (cluster %d): expected %x; got %x", index, cindex, binary.LittleEndian.Uint64(seg.Checksum[:8]), murmur3.SeedSum64(0xE2236FDC26A5F6D2, decomp))
							}
						default:
							return fmt.Errorf("unsupported checksum type: %d", rootHdr.Checksum)
						}
						/* write decompressed data to file */
						if _, err := outfile.WriteAt(decomp, pos); err != nil {
							return fmt.Errorf("failed to write decompressed decrypted data to file: %v", err)
						}
					}
					return nil
				})
			}(idx, segmentData, seg.DecompressedSize)
		}

		if err := eg.Wait(); err != nil {
			return fmt.Errorf("failed to decrypt cluster #%d: %v", cindex, err)
		}

		clusterMAC = nextClusterMac
		cindex++

		if totalSize >= rootHdr.FileSize {
			break
		}
	}

	/* padding key */
	var paddingKey headerKey
	if err := binary.Read(
		hkdf.New(sha256.New, mainKey, []byte{}, []byte(PaddingKeyInfo)),
		binary.LittleEndian,
		&paddingKey,
	); err != nil {
		return fmt.Errorf("failed to derive padding key: %v", err)
	}
	paddingData, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("failed to read padding data: %v", err)
	}
	if len(paddingData) != 0 {
		decryptedPadding, err := decryptCTR(paddingData, paddingKey.Key[:], paddingKey.IV[:])
		if err != nil {
			return fmt.Errorf("failed to decrypt segment data: %v", err)
		}
		log.Debugf("PADDING:\n%s", hex.Dump(decryptedPadding))
		phmac := hmac.New(sha256.New, paddingKey.MAC[:])
		if _, err := phmac.Write(paddingData); err != nil {
			return fmt.Errorf("failed to write padding data HMAC: %v", err)
		}
		if !hmac.Equal(clusterMAC[:], phmac.Sum(nil)) {
			return fmt.Errorf("invalid padding HMAC: %x; expected %x", phmac.Sum(nil), paddingKey.IV)
		}
	}

	return nil
}

func decrypt(in, out string, symmetricKey []byte) (string, error) {
	f, err := os.Open(in)
	if err != nil {
		return "", fmt.Errorf("decrypt: failed to open AEA file: %v", err)
	}
	defer f.Close()

	var hdr Header
	if err := binary.Read(f, binary.LittleEndian, &hdr); err != nil {
		return "", fmt.Errorf("failed to read AEA header: %v", err)
	}

	if string(hdr.Magic[:]) != Magic {
		return "", fmt.Errorf("invalid AEA header: found '%s' expected '%s'", string(hdr.Magic[:]), Magic)
	}

	if hdr.ProfileID() != SymmetricEncryption {
		return "", fmt.Errorf("invalid profile: %d; expected %d", hdr.ProfileID(), SymmetricEncryption)
	}

	authData := make([]byte, hdr.AuthDataLength)
	if _, err := f.Read(authData); err != nil {
		return "", fmt.Errorf("failed to read auth data: %v", err)
	}

	mainSalt := make([]byte, 32)
	if _, err := f.Read(mainSalt); err != nil {
		return "", fmt.Errorf("failed to read main salt: %v", err)
	}

	/* main key */
	mainKey, err := deriveKey(
		symmetricKey,
		mainSalt,
		binary.LittleEndian.AppendUint32(
			[]byte(MainKeyInfo),
			hdr.ProfileAndScryptStrength,
		))
	if err != nil {
		return "", fmt.Errorf("failed to derive main key: %v", err)
	}

	var encRootHdr encRootHeader
	if err := binary.Read(f, binary.LittleEndian, &encRootHdr); err != nil {
		return "", fmt.Errorf("failed to read encrypted root header: %v", err)
	}

	/* root header */
	var rootHdrKey headerKey
	if err := binary.Read(
		hkdf.New(sha256.New, mainKey, []byte{}, []byte(RootHeaderEncryptedKeyInfo)),
		binary.LittleEndian,
		&rootHdrKey,
	); err != nil {
		return "", fmt.Errorf("failed to derive root header key: %v", err)
	}
	// verify root header HMAC
	rhmac, err := getHMAC(rootHdrKey.MAC[:], encRootHdr.Data[:], slices.Concat(encRootHdr.ClusterHmac[:], authData[:]))
	if err != nil {
		return "", fmt.Errorf("failed to get encrypted root header HMAC: %v", err)
	}
	if !hmac.Equal(encRootHdr.Hmac[:], rhmac[:]) {
		return "", fmt.Errorf("invalid root header HMAC: %x; expected %x", encRootHdr.Hmac, rhmac)
	}
	rootHdrData, err := decryptCTR(append(encRootHdr.Data[:], authData...), rootHdrKey.Key[:], rootHdrKey.IV[:])
	if err != nil {
		return "", fmt.Errorf("failed to decrypt root header: %v", err)
	}
	var rootHdr RootHeader
	if err := binary.Read(bytes.NewReader(rootHdrData), binary.LittleEndian, &rootHdr); err != nil {
		return "", err
	}

	of, err := os.Create(out)
	if err != nil {
		return "", fmt.Errorf("failed to create output file: %v", err)
	}
	defer of.Close()

	if err := decryptClusters(context.Background(), f, of, mainKey, encRootHdr.ClusterHmac, rootHdr); err != nil {
		log.WithError(err).Error("failed to decrypt cluster")
	}

	finfo, err := of.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to get output file info: %v", err)
	}
	if int(finfo.Size()) != int(rootHdr.FileSize) {
		return "", fmt.Errorf("invalid file size: %d; expected %d", finfo.Size(), rootHdr.FileSize)
	}

	return out, nil
}

type DecryptConfig struct {
	Input       string // Input AEA file
	Output      string // Output directory
	PrivKeyData []byte // Private key data
	B64SymKey   string // Base64 encoded Symmetric encryption key
	PemDB       string // Path to PEM database

	symEncKey []byte // Symmetric encryption key bytes
}

func Decrypt(c *DecryptConfig) (string, error) {
	metadata, err := Info(c.Input)
	if err != nil {
		return "", fmt.Errorf("failed to Decrypt AEA: %v", err)
	}

	if encKey, ok := metadata["encryption_key"]; ok {
		c.symEncKey, err = hex.DecodeString(string(encKey))
		if err != nil {
			return "", fmt.Errorf("failed to decode hex sym key: %v", err)
		}
		c.B64SymKey = base64.StdEncoding.EncodeToString(c.symEncKey)
	} else if c.B64SymKey == "" {
		c.symEncKey, err = metadata.DecryptFCS(c.PrivKeyData, c.PemDB)
		if err != nil {
			return "", fmt.Errorf("failed to HPKE decrypt fcs-key: %v", err)
		}
		c.B64SymKey = base64.StdEncoding.EncodeToString(c.symEncKey)
	} else {
		c.symEncKey, err = base64.StdEncoding.WithPadding(base64.StdPadding).DecodeString(c.B64SymKey)
		if err != nil {
			return "", fmt.Errorf("failed to decode base64 sym key: %v", err)
		}
	}

	// if true { // uncomment this is to test the pure Go implementation on darwin
	if _, err := os.Stat(aeaBinPath); os.IsNotExist(err) { // 'aea' binary NOT found (linux/windows)
		log.Info("Using pure Go implementation for AEA decryption")
		return decrypt(c.Input, filepath.Join(c.Output, filepath.Base(strings.TrimSuffix(c.Input, filepath.Ext(c.Input)))), c.symEncKey)
	}
	// use 'aea' binary (as is the fastest way to decrypt AEA on macOS)
	return aea(
		c.Input,
		filepath.Join(c.Output, filepath.Base(strings.TrimSuffix(c.Input, filepath.Ext(c.Input)))),
		c.B64SymKey,
	)
}

func aea(in, out, key string) (string, error) {
	if runtime.GOOS == "darwin" {
		if err := os.MkdirAll(filepath.Dir(out), 0o750); err != nil {
			return "", fmt.Errorf("failed to create output directory '%s': %v", filepath.Dir(out), err)
		}
		cmd := exec.Command(aeaBinPath, "decrypt", "-i", in, "-o", out, "-key-value", fmt.Sprintf("base64:%s", key))
		cout, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("failed to decrypt using '%s' (bad key?) %v: %s", aeaBinPath, err, cout)
		}
		return out, nil
	}
	return "", fmt.Errorf("only supported on macOS (due to `aea` binary requirement)")
}
