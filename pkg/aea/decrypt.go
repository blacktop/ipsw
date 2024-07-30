package aea

//go:generate stringer -type=compressionType -output aea_string.go

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
	"github.com/dustin/go-humanize"
	"github.com/twmb/murmur3"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/sync/errgroup"
)

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
	RawSize          uint32
	Checksum         [32]byte
}

type work struct {
	ClusterIndex uint32
	Data         []byte
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

func decryptCluster(ctx context.Context, r io.ReadSeeker, mainKey []byte, clusterMAC HMAC, rootHdr RootHeader, out chan work) error {
	defer close(out)
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
			return err
		}

		// read segment headers
		var clusterHeaderKey headerKey
		if err := binary.Read(
			hkdf.New(sha256.New, clusterKey, []byte{}, []byte(ClusterKeyMaterialInfo)),
			binary.LittleEndian,
			&clusterHeaderKey,
		); err != nil {
			return err
		}
		encSegmmentHdrData := make([]byte, segmentHeaderSize*rootHdr.SegmentsPerCluster)
		if _, err := r.Read(encSegmmentHdrData); err != nil {
			return err
		}
		var nextClusterMac HMAC
		if err := binary.Read(r, binary.LittleEndian, &nextClusterMac); err != nil {
			return err
		}
		segmentMacData := make([]byte, 32*rootHdr.SegmentsPerCluster)
		if _, err := r.Read(segmentMacData); err != nil {
			return err
		}
		shmac := hmac.New(sha256.New, clusterHeaderKey.MAC[:])
		ssalt := slices.Concat(nextClusterMac[:], segmentMacData)
		if _, err := shmac.Write(slices.Concat(
			ssalt,
			binary.LittleEndian.AppendUint64(
				[]byte(encSegmmentHdrData[:]),
				uint64(len(ssalt)),
			),
		)); err != nil {
			return err
		}
		if !hmac.Equal(clusterMAC[:], shmac.Sum(nil)) {
			return fmt.Errorf("invalid cluster #%d HMAC: %x; expected %x", cindex, clusterMAC, shmac.Sum(nil))
		} else {
			log.Debugf("Cluster %d HMAC OK", cindex)
		}
		segmentMACs := make([]HMAC, rootHdr.SegmentsPerCluster)
		if err := binary.Read(bytes.NewReader(segmentMacData), binary.LittleEndian, &segmentMACs); err != nil {
			return err
		}
		segmmentHdrData, err := decryptCTR(encSegmmentHdrData, clusterHeaderKey.Key[:], clusterHeaderKey.IV[:])
		if err != nil {
			return err
		}
		segmentHdrs := make([]SegmentHeader, rootHdr.SegmentsPerCluster)
		if err := binary.Read(bytes.NewReader(segmmentHdrData), binary.LittleEndian, segmentHdrs); err != nil {
			return err
		}

		// decrypt segments
		segments := make([][]byte, 256)
		for idx, seg := range segmentHdrs {
			totalSize += uint64(seg.DecompressedSize)
			if seg.DecompressedSize == 0 {
				continue
			}
			segmentData := make([]byte, seg.RawSize)
			if _, err = r.Read(segmentData); err != nil {
				return err
			}
			func(index int, data []byte, size uint32) {
				eg.Go(func() error {
					info := new(bytes.Buffer)
					if err := binary.Write(info, binary.LittleEndian, []byte(SegmentKeyInfo)); err != nil {
						return err
					}
					if err := binary.Write(info, binary.LittleEndian, uint32(index)); err != nil {
						return err
					}
					var segmentKey headerKey
					if err := binary.Read(
						hkdf.New(sha256.New, clusterKey, []byte{}, info.Bytes()),
						binary.LittleEndian,
						&segmentKey,
					); err != nil {
						return err
					}
					shmac := hmac.New(sha256.New, segmentKey.MAC[:])
					if _, err := shmac.Write(slices.Concat(
						[]byte{},
						binary.LittleEndian.AppendUint64(
							[]byte(data[:]),
							uint64(len([]byte{})),
						),
					)); err != nil {
						return err
					}
					if !hmac.Equal(segmentMACs[index][:], shmac.Sum(nil)) {
						return fmt.Errorf("invalid segment #%d HMAC: %x; expected %x", index, segmentMACs[index], shmac.Sum(nil))
					}
					decryptedData, err := decryptCTR(data, segmentKey.Key[:], segmentKey.IV[:])
					if err != nil {
						return err
					}
					switch rootHdr.Compression {
					// TODO: https://github.com/pierrec/lz4
					// TODO: https://pkg.go.dev/github.com/ulikunitz/xz/lzma
					case NONE:
						log.WithFields(log.Fields{
							"cluster": cindex,
							"segment": index,
							"size":    humanize.IBytes(uint64(len(decryptedData))),
							"all":     len(decryptedData) == int(size),
						}).Debug("NOCOMPRESS")
						segments[index] = decryptedData
					// <-decryptedData
					case LZMA:
						var decomp []byte
						lzfse.DecodeLZVNBuffer(decryptedData, decomp)
						log.WithFields(log.Fields{
							"cluster": cindex,
							"segment": index,
							"size":    humanize.IBytes(uint64(len(decomp))),
							"all":     len(decomp) == int(size),
						}).Debug("LZMA")
						segments[index] = decomp[:seg.DecompressedSize]
					case LZBITMAP:
						var decomp []byte
						lzfse.LzBitMapDecompress(decryptedData, decomp)
						log.WithFields(log.Fields{
							"cluster": cindex,
							"segment": index,
							"size":    humanize.IBytes(uint64(len(decomp))),
							"all":     len(decomp) == int(size),
						}).Debug("LZBITMAP")
						segments[index] = decomp[:seg.DecompressedSize]
					case LZFSE:
						if seg.DecompressedSize == seg.RawSize { // FIXME: why is this NONE ??
							segments[index] = decryptedData
							break
						}
						decomp := lzfse.DecodeBuffer(decryptedData)
						log.WithFields(log.Fields{
							"cluster": cindex,
							"segment": index,
							"size":    humanize.IBytes(uint64(len(decomp))),
							"all":     len(decomp) == int(size),
						}).Debug("LZFSE")
						segments[index] = decomp[:seg.DecompressedSize]
					case ZLIB:
						zr, err := zlib.NewReader(bytes.NewReader(decryptedData))
						if err != nil {
							return err
						}
						segments[index], err = io.ReadAll(zr)
						if err != nil {
							return err
						}
						log.WithFields(log.Fields{
							"cluster": cindex,
							"segment": index,
							"size":    humanize.IBytes(uint64(len(segments[index]))),
							"all":     len(segments[index]) == int(size),
						}).Debug("ZLIB")
					// <-decomp
					default:
						return fmt.Errorf("unsupported compression type: %s", rootHdr.Compression)
					}
					switch rootHdr.Checksum {
					case None:
					case Sha256:
						if sha256.Sum256(segments[index]) != seg.Checksum {
							return fmt.Errorf("invalid SHA256 checksum for segment %d (cluster %d): expected %x; got %x", index, cindex, seg.Checksum, sha256.Sum256(segments[index]))
						}
					case Murmur:
						if murmur3.SeedSum64(0xE2236FDC26A5F6D2, segments[index]) != binary.LittleEndian.Uint64(seg.Checksum[:8]) {
							return fmt.Errorf("invalid MURMUR checksum for segment %d (cluster %d): expected %x; got %x", index, cindex, seg.Checksum, murmur3.Sum64(segments[index]))
						}
					default:
						return fmt.Errorf("unsupported checksum type: %d", rootHdr.Checksum)
					}
					return nil
				})
			}(idx, segmentData, seg.DecompressedSize)
		}

		if err := eg.Wait(); err != nil {
			return err
		}

		out <- work{ClusterIndex: cindex, Data: bytes.Join(segments, nil)}

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
		return err
	}
	paddingData, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	phmac := hmac.New(sha256.New, paddingKey.MAC[:])
	if _, err := phmac.Write(paddingData); err != nil {
		return err
	}
	if !hmac.Equal(clusterMAC[:], phmac.Sum(nil)) {
		return fmt.Errorf("invalid padding HMAC: %x; expected %x", phmac.Sum(nil), paddingKey.IV)
	}

	return nil
}

func aeaDecrypt(in, out string, symmetricKey []byte) (string, error) {
	f, err := os.Open(in)
	if err != nil {
		return "", err
	}
	defer f.Close()

	var hdr Header
	if err := binary.Read(f, binary.LittleEndian, &hdr); err != nil {
		return "", err
	}

	if string(hdr.Magic[:]) != Magic {
		return "", fmt.Errorf("invalid AEA header: found '%s' expected '%s'", string(hdr.Magic[:]), Magic)
	}

	if hdr.ProfileID() != SymmetricEncryption {
		return "", fmt.Errorf("invalid profile: %d; expected %d", hdr.ProfileID(), SymmetricEncryption)
	}

	authData := make([]byte, hdr.AuthDataLength)
	if _, err := f.Read(authData); err != nil {
		return "", err
	}

	mainSalt := make([]byte, 32)
	if _, err := f.Read(mainSalt); err != nil {
		return "", err
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
		return "", err
	}

	var encRootHdr encRootHeader
	if err := binary.Read(f, binary.LittleEndian, &encRootHdr); err != nil {
		return "", err
	}

	/* root header */
	var rootHdrKey headerKey
	if err := binary.Read(
		hkdf.New(sha256.New, mainKey, []byte{}, []byte(RootHeaderEncryptedKeyInfo)),
		binary.LittleEndian,
		&rootHdrKey,
	); err != nil {
		return "", err
	}
	// verify root header HMAC
	rsalt := slices.Concat(encRootHdr.ClusterHmac[:], authData[:])
	rhmac := hmac.New(sha256.New, rootHdrKey.MAC[:])
	if _, err := rhmac.Write(slices.Concat(
		rsalt,
		binary.LittleEndian.AppendUint64(
			[]byte(encRootHdr.Data[:]),
			uint64(len(rsalt)),
		),
	)); err != nil {
		return "", err
	}
	if !hmac.Equal(encRootHdr.Hmac[:], rhmac.Sum(nil)) {
		return "", fmt.Errorf("invalid root header HMAC: %x; expected %x", encRootHdr.Hmac, rhmac.Sum(nil))
	}
	rootHdrData, err := decryptCTR(append(encRootHdr.Data[:], authData...), rootHdrKey.Key[:], rootHdrKey.IV[:])
	if err != nil {
		return "", err
	}
	var rootHdr RootHeader
	if err := binary.Read(bytes.NewReader(rootHdrData), binary.LittleEndian, &rootHdr); err != nil {
		return "", err
	}

	dec := make(chan work) // decrypted data channel

	go func() {
		if err := decryptCluster(context.Background(), f, mainKey, encRootHdr.ClusterHmac, rootHdr, dec); err != nil {
			log.WithError(err).Error("failed to decrypt cluster")
		}
	}()

	of, err := os.Create(out)
	if err != nil {
		return "", err
	}
	defer of.Close()

	total := 0
	for d := range dec {
		log.Debugf("Writing cluster %d", d.ClusterIndex)
		if n, err := of.Write(d.Data); err != nil {
			return "", err
		} else {
			log.Debugf("Wrote %s", humanize.Bytes(uint64(n)))
			total += n
		}
	}
	log.Debugf("TOTAL: %s", humanize.Bytes(uint64(total)))
	if total != int(rootHdr.FileSize) {
		return "", fmt.Errorf("invalid file size: %d; expected %d", total, rootHdr.FileSize)
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
		return "", fmt.Errorf("failed to parse AEA: %v", err)
	}

	if c.B64SymKey == "" {
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

	// if true {
	if _, err := os.Stat(aeaBinPath); os.IsNotExist(err) { // 'aea' binary NOT found (linux/windows)
		log.Info("Using pure Go implementation for AEA decryption")
		return aeaDecrypt(c.Input, filepath.Join(c.Output, filepath.Base(strings.TrimSuffix(c.Input, filepath.Ext(c.Input)))), c.symEncKey)
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
		cmd := exec.Command(aeaBinPath, "decrypt", "-i", in, "-o", out, "-key-value", fmt.Sprintf("base64:%s", key))
		cout, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("failed to decrypt using '%s' (bad key?) %v: %s", aeaBinPath, err, cout)
		}
		return out, nil
	}
	return "", fmt.Errorf("only supported on macOS (due to `aea` binary requirement)")
}
