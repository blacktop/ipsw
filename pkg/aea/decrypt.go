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
	"strings"
	"sync"

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

// decryptCTRInPlace decrypts ciphertext in-place, modifying the input slice
func decryptCTRInPlace(data, key, iv []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create new AES cipher: %v", err)
	}
	cipher.NewCTR(block, iv).XORKeyStream(data, data)
	return nil
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
	// Write salt first
	if len(salt) > 0 {
		if _, err := mac.Write(salt); err != nil {
			return HMAC{}, fmt.Errorf("failed to write salt to HMAC: %v", err)
		}
	}
	// Write data
	if _, err := mac.Write(data); err != nil {
		return HMAC{}, fmt.Errorf("failed to write data to HMAC: %v", err)
	}
	// Write salt length as uint64
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], uint64(len(salt)))
	if _, err := mac.Write(lenBuf[:]); err != nil {
		return HMAC{}, fmt.Errorf("failed to write length to HMAC: %v", err)
	}
	return HMAC(mac.Sum(nil)), nil
}

// bufferPool is used to reuse byte slices for segment data to reduce allocations
type bufferPool struct {
	pool sync.Pool
}

func newBufferPool() *bufferPool {
	return &bufferPool{
		pool: sync.Pool{
			New: func() any {
				// Start with a reasonable default size; will grow as needed
				b := make([]byte, 0, 1<<20) // 1MB initial capacity
				return &b
			},
		},
	}
}

func (p *bufferPool) get(size int) []byte {
	buf := p.pool.Get().(*[]byte)
	if cap(*buf) < size {
		// Need a larger buffer
		*buf = make([]byte, size)
	} else {
		*buf = (*buf)[:size]
	}
	return *buf
}

func (p *bufferPool) put(buf []byte) {
	// Keep the buffer for reuse
	b := buf[:0]
	p.pool.Put(&b)
}

func decryptClusters(ctx context.Context, r io.ReadSeeker, outfile *os.File, mainKey []byte, clusterMAC HMAC, rootHdr RootHeader) error {
	// Limit concurrent goroutines to prevent resource exhaustion
	// Use fewer workers to reduce peak memory (each worker holds ~2MB for segment + decomp)
	maxWorkers := min(runtime.GOMAXPROCS(0), 4)

	// Buffer pool for segment data to reduce allocations
	segPool := newBufferPool()
	decompPool := newBufferPool()

	segmentHeaderSize := checksumSize[rootHdr.Checksum] + 8
	cindex := uint32(0)
	totalSize := uint64(0)

	// Pre-allocate reusable buffers for cluster-level data
	encSegmentHdrData := make([]byte, segmentHeaderSize*rootHdr.SegmentsPerCluster)
	segmentMacData := make([]byte, 32*rootHdr.SegmentsPerCluster)
	segmentMACs := make([]HMAC, rootHdr.SegmentsPerCluster)
	segmentHdrs := make([]SegmentHeader, rootHdr.SegmentsPerCluster)

	// Pre-allocate segment key info buffer
	segKeyInfoBuf := make([]byte, len(SegmentKeyInfo)+4)
	copy(segKeyInfoBuf, SegmentKeyInfo)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Create a new errgroup for each cluster to avoid context reuse issues
		eg, egCtx := errgroup.WithContext(ctx)
		eg.SetLimit(maxWorkers)
		_ = egCtx // used for cancellation propagation via errgroup

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
		if _, err := io.ReadFull(r, encSegmentHdrData); err != nil {
			return fmt.Errorf("failed to read encrypted segment headers data: %v", err)
		}
		var nextClusterMac HMAC
		if err := binary.Read(r, binary.LittleEndian, &nextClusterMac); err != nil {
			return fmt.Errorf("failed to read next cluster HMAC: %v", err)
		}
		if _, err := io.ReadFull(r, segmentMacData); err != nil {
			return fmt.Errorf("failed to read segment HMAC data: %v", err)
		}

		// Build salt for HMAC without allocating (reuse existing slices)
		hmacSalt := make([]byte, len(nextClusterMac)+len(segmentMacData))
		copy(hmacSalt, nextClusterMac[:])
		copy(hmacSalt[len(nextClusterMac):], segmentMacData)

		shmac, err := getHMAC(clusterHeaderKey.MAC[:], encSegmentHdrData, hmacSalt)
		if err != nil {
			return fmt.Errorf("failed to get HMAC for encrypted segment headers data: %v", err)
		}
		if !hmac.Equal(clusterMAC[:], shmac[:]) {
			return fmt.Errorf("invalid cluster #%d HMAC: %x; expected %x", cindex, clusterMAC, shmac)
		}
		if err := binary.Read(bytes.NewReader(segmentMacData), binary.LittleEndian, &segmentMACs); err != nil {
			return fmt.Errorf("failed to read segment HMACs: %v", err)
		}
		segmentHdrData, err := decryptCTR(encSegmentHdrData, clusterHeaderKey.Key[:], clusterHeaderKey.IV[:])
		if err != nil {
			return fmt.Errorf("failed to decrypt segment headers: %v", err)
		}
		if err := binary.Read(bytes.NewReader(segmentHdrData), binary.LittleEndian, segmentHdrs); err != nil {
			return fmt.Errorf("failed to read segment headers: %v", err)
		}

		// decrypt segments with limited concurrency
		currentClusterIdx := cindex // capture for goroutines
		for idx, seg := range segmentHdrs {
			if seg.DecompressedSize == 0 {
				continue
			}
			totalSize += uint64(seg.DecompressedSize)

			// Read segment data (must be done sequentially from the reader)
			// Get buffer from pool instead of allocating
			segmentData := segPool.get(int(seg.CompressedSize))
			if _, err = io.ReadFull(r, segmentData); err != nil {
				segPool.put(segmentData)
				return fmt.Errorf("failed to read segment data: %v", err)
			}

			// Capture loop variables for goroutine
			segIdx := idx
			segHdr := seg
			segData := segmentData
			segMAC := segmentMACs[idx]
			clKey := clusterKey // capture cluster key for this cluster

			eg.Go(func() error {
				// Ensure we return the buffer to the pool when done
				defer segPool.put(segData)

				pos := int64(currentClusterIdx)*int64(rootHdr.SegmentSize)*int64(rootHdr.SegmentsPerCluster) +
					int64(segIdx)*int64(rootHdr.SegmentSize)

				// Derive segment key
				keyInfo := make([]byte, len(SegmentKeyInfo)+4)
				copy(keyInfo, SegmentKeyInfo)
				binary.LittleEndian.PutUint32(keyInfo[len(SegmentKeyInfo):], uint32(segIdx))

				var segmentKey headerKey
				if err := binary.Read(
					hkdf.New(sha256.New, clKey, []byte{}, keyInfo),
					binary.LittleEndian,
					&segmentKey,
				); err != nil {
					return fmt.Errorf("failed to derive segment key: %v", err)
				}

				// Verify HMAC
				shmac, err := getHMAC(segmentKey.MAC[:], segData, nil)
				if err != nil {
					return fmt.Errorf("failed to get HMAC for segment header: %v", err)
				}
				if !hmac.Equal(segMAC[:], shmac[:]) {
					return fmt.Errorf("invalid segment #%d HMAC: %x; expected %x", segIdx, segMAC, shmac)
				}

				// Decrypt in-place to avoid allocation
				if err := decryptCTRInPlace(segData, segmentKey.Key[:], segmentKey.IV[:]); err != nil {
					return fmt.Errorf("failed to decrypt segment data: %v", err)
				}

				// Handle uncompressed data
				if segHdr.DecompressedSize == segHdr.CompressedSize {
					if _, err := outfile.WriteAt(segData, pos); err != nil {
						return fmt.Errorf("failed to write uncompressed decrypted data to file: %v", err)
					}
					return nil
				}

				// Decompress - use pool for buffers where we control allocation
				var decomp []byte
				var decompFromPool bool
				switch rootHdr.Compression {
				case NONE:
					decomp = segData
				case LZBITMAP:
					decomp = decompPool.get(int(segHdr.DecompressedSize))
					decompFromPool = true
					lzfse.LzBitMapDecompress(segData, decomp)
				case LZFSE:
					// Use our own decodeLZFSE that takes a pre-allocated buffer
					decomp = decompPool.get(int(segHdr.DecompressedSize))
					decompFromPool = true
					n := decodeLZFSE(segData, decomp)
					if n == 0 {
						decompPool.put(decomp)
						return fmt.Errorf("failed to decompress LZFSE segment %d", segIdx)
					}
					decomp = decomp[:n]
				case LZMA:
					decomp = decompPool.get(int(segHdr.DecompressedSize))
					decompFromPool = true
					lzfse.DecodeLZVNBuffer(segData, decomp)
				case ZLIB:
					// Use pool buffer and read into it
					decomp = decompPool.get(int(segHdr.DecompressedSize))
					decompFromPool = true
					zr, err := zlib.NewReader(bytes.NewReader(segData))
					if err != nil {
						decompPool.put(decomp)
						return fmt.Errorf("failed to create zlib reader: %v", err)
					}
					n, err := io.ReadFull(zr, decomp)
					zr.Close()
					if err != nil && err != io.ErrUnexpectedEOF {
						decompPool.put(decomp)
						return fmt.Errorf("failed to read zlib decompressed data: %v", err)
					}
					decomp = decomp[:n]
				default:
					return fmt.Errorf("unsupported compression type: %s", rootHdr.Compression)
				}

				// Verify checksum
				switch rootHdr.Checksum {
				case None:
					// no checksum
				case Sha256:
					computed := sha256.Sum256(decomp)
					if computed != segHdr.Checksum {
						if decompFromPool {
							decompPool.put(decomp)
						}
						return fmt.Errorf("invalid SHA256 checksum for segment %d (cluster %d): expected %x; got %x", segIdx, currentClusterIdx, segHdr.Checksum, computed)
					}
				case Murmur:
					computed := murmur3.SeedSum64(0xE2236FDC26A5F6D2, decomp)
					expected := binary.LittleEndian.Uint64(segHdr.Checksum[:8])
					if computed != expected {
						if decompFromPool {
							decompPool.put(decomp)
						}
						return fmt.Errorf("invalid MURMUR checksum for segment %d (cluster %d): expected %x; got %x", segIdx, currentClusterIdx, expected, computed)
					}
				default:
					if decompFromPool {
						decompPool.put(decomp)
					}
					return fmt.Errorf("unsupported checksum type: %d", rootHdr.Checksum)
				}

				// Write decompressed data to file
				if _, err := outfile.WriteAt(decomp, pos); err != nil {
					if decompFromPool {
						decompPool.put(decomp)
					}
					return fmt.Errorf("failed to write decompressed decrypted data to file: %v", err)
				}

				// Return decompression buffer to pool
				if decompFromPool {
					decompPool.put(decomp)
				}
				return nil
			})
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
	// Build HMAC salt without allocation
	hmacSalt := make([]byte, len(encRootHdr.ClusterHmac)+len(authData))
	copy(hmacSalt, encRootHdr.ClusterHmac[:])
	copy(hmacSalt[len(encRootHdr.ClusterHmac):], authData)
	// verify root header HMAC
	rhmac, err := getHMAC(rootHdrKey.MAC[:], encRootHdr.Data[:], hmacSalt)
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
		return "", fmt.Errorf("failed to decrypt clusters: %v", err)
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
	Proxy       string // HTTP/HTTPS proxy
	Insecure    bool   // Allow insecure connections (skip TLS verification)

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
		c.symEncKey, err = metadata.DecryptFCS(c.PrivKeyData, c.PemDB, c.Proxy, c.Insecure)
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
	out, err := aea(
		c.Input,
		filepath.Join(c.Output, filepath.Base(strings.TrimSuffix(c.Input, filepath.Ext(c.Input)))),
		c.B64SymKey,
	)
	if err != nil {
		// fallback to pure Go implementation if system binary fails
		// (can happen due to resource exhaustion or other transient errors)
		log.WithError(err).Warn("System 'aea' binary failed, falling back to pure Go implementation")
		return decrypt(c.Input, filepath.Join(c.Output, filepath.Base(strings.TrimSuffix(c.Input, filepath.Ext(c.Input)))), c.symEncKey)
	}
	return out, nil
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
