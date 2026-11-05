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
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/lzfse-cgo"
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

func cryptCTR(data, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create new AES cipher: %v", err)
	}
	result := make([]byte, len(data))
	cipher.NewCTR(block, iv).XORKeyStream(result, data)
	return result, nil
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

func getHMAC(key, data, salt []byte) HMAC {
	mac := hmac.New(sha256.New, key)
	if len(salt) > 0 {
		mac.Write(salt)
	}
	mac.Write(data)
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], uint64(len(salt)))
	mac.Write(lenBuf[:])
	return HMAC(mac.Sum(nil))
}

func getRootHeaderHMAC(key, data []byte, clusterMAC HMAC, authData io.Reader, authSize uint32) (HMAC, error) {
	mac := hmac.New(sha256.New, key)
	mac.Write(clusterMAC[:])
	if _, err := io.CopyN(mac, authData, int64(authSize)); err != nil {
		return HMAC{}, fmt.Errorf("failed to read auth data: %w", err)
	}
	mac.Write(data)
	mac.Write(binary.LittleEndian.AppendUint64(nil, uint64(len(clusterMAC))+uint64(authSize)))
	return HMAC(mac.Sum(nil)), nil
}

// AEA uses MurmurHash2's 64-bit variant, not MurmurHash3.
func murmur64(data []byte) uint64 {
	const multiplier uint64 = 0xc6a4a7935bd1e995
	h := uint64(0xE2236FDC26A5F6D2) ^ uint64(len(data))*multiplier
	for len(data) >= 8 {
		k := binary.LittleEndian.Uint64(data)
		k *= multiplier
		k ^= k >> 47
		k *= multiplier
		h = (h ^ k) * multiplier
		data = data[8:]
	}
	for i, b := range data {
		h ^= uint64(b) << (8 * i)
	}
	if len(data) != 0 {
		h *= multiplier
	}
	h ^= h >> 47
	h *= multiplier
	return h ^ (h >> 47)
}

// The LZBITMAP wrapper discards out_len. Chunk headers carry the same output
// lengths that the C decoder sums, so validate them before reusing a buffer.
func validateLZBitmapSize(data []byte, remaining int) error {
	if len(data) < 4 || binary.LittleEndian.Uint32(data) != 0x094d425a {
		return fmt.Errorf("invalid LZBITMAP magic")
	}
	data = data[4:]
	for len(data) >= 6 {
		compressed := int(data[0]) | int(data[1])<<8 | int(data[2])<<16
		decoded := int(data[3]) | int(data[4])<<8 | int(data[5])<<16
		if compressed < 6 || compressed > len(data) || decoded > 0x8000 || decoded > remaining {
			return fmt.Errorf("invalid LZBITMAP chunk size")
		}
		remaining -= decoded
		data = data[compressed:]
		if decoded == 0 {
			if remaining != 0 {
				return fmt.Errorf("short LZBITMAP output: missing %d bytes", remaining)
			}
			return nil
		}
	}
	return fmt.Errorf("missing LZBITMAP terminator")
}

const (
	// Limits exposed by Apple's AEAContext setters.
	maxAEASegmentSize        = 256 << 20
	maxAEASegmentsPerCluster = 256 << 10
	decryptMemoryBudget      = 32 << 20
	maxDecryptWorkers        = 8
)

type decryptSegment struct {
	cluster, index uint32
	header         SegmentHeader
	mac            HMAC
	clusterPRK     []byte
	input, output  int64
}

type segmentDecoder struct {
	data, decoded, scratch []byte
}

type decryptedSegment struct {
	data   []byte
	offset int64
	done   chan struct{}
}

func (d *segmentDecoder) decrypt(r io.ReaderAt, job decryptSegment, compression compressionType, checksum checksumType) ([]byte, error) {
	size := int(job.header.CompressedSize)
	if cap(d.data) < size {
		d.data = make([]byte, size)
	}
	data := d.data[:size]
	if _, err := r.ReadAt(data, job.input); err != nil {
		return nil, fmt.Errorf("failed to read segment data: %w", err)
	}
	var keyInfo [len(SegmentKeyInfo) + 4]byte
	copy(keyInfo[:], SegmentKeyInfo)
	binary.LittleEndian.PutUint32(keyInfo[len(SegmentKeyInfo):], job.index)
	var key headerKey
	if err := binary.Read(hkdf.Expand(sha256.New, job.clusterPRK, keyInfo[:]), binary.LittleEndian, &key); err != nil {
		return nil, fmt.Errorf("failed to derive segment key: %w", err)
	}
	mac := getHMAC(key.MAC[:], data, nil)
	if !hmac.Equal(job.mac[:], mac[:]) {
		return nil, fmt.Errorf("invalid segment #%d HMAC: %x; expected %x", job.index, job.mac, mac)
	}
	if err := decryptCTRInPlace(data, key.Key[:], key.IV[:]); err != nil {
		return nil, fmt.Errorf("failed to decrypt segment data: %w", err)
	}

	plain := data
	if job.header.CompressedSize != job.header.DecompressedSize {
		size := int(job.header.DecompressedSize)
		// Buffer decoders may report a full destination after truncating an
		// overlong stream. One extra byte makes that distinguishable.
		if cap(d.decoded) < size+1 {
			d.decoded = make([]byte, size+1)
		}
		plain = d.decoded[:size]
		switch compression {
		case LZBITMAP:
			if err := validateLZBitmapSize(data, size); err != nil {
				return nil, err
			}
			if status := lzfse.LzBitMapDecompress(data, plain); status != 0 {
				return nil, fmt.Errorf("failed to decompress LZBITMAP segment %d: status %d", job.index, status)
			}
		case LZFSE:
			if d.scratch == nil {
				d.scratch = make([]byte, lzfse.DecodeScratchSize())
			}
			if n := lzfse.DecodeBufferWithScratch(data, d.decoded[:size+1], d.scratch); n != size {
				return nil, fmt.Errorf("invalid LZFSE segment %d size: got %d; expected %d", job.index, n, size)
			}
		case LZMA:
			if n := lzfse.DecodeLZVNBuffer(data, d.decoded[:size+1]); n != uint(size) {
				return nil, fmt.Errorf("invalid LZVN segment %d size: got %d; expected %d", job.index, n, size)
			}
		case ZLIB:
			zr, err := zlib.NewReader(bytes.NewReader(data))
			if err != nil {
				return nil, fmt.Errorf("failed to create zlib reader: %w", err)
			}
			defer zr.Close()
			if _, err := io.ReadFull(zr, plain); err != nil {
				return nil, fmt.Errorf("failed to read zlib decompressed data: %w", err)
			}
			var extra [1]byte
			if n, err := zr.Read(extra[:]); n != 0 || err != io.EOF {
				return nil, fmt.Errorf("invalid zlib segment %d size or checksum", job.index)
			}
		default:
			return nil, fmt.Errorf("unsupported compression type: %s", compression)
		}
	}

	switch checksum {
	case None:
	case Sha256:
		if computed := sha256.Sum256(plain); computed != job.header.Checksum {
			return nil, fmt.Errorf("invalid SHA256 checksum for segment %d (cluster %d): expected %x; got %x", job.index, job.cluster, job.header.Checksum, computed)
		}
	case Murmur:
		expected := binary.LittleEndian.Uint64(job.header.Checksum[:8])
		if computed := murmur64(plain); computed != expected {
			return nil, fmt.Errorf("invalid MURMUR checksum for segment %d (cluster %d): expected %x; got %x", job.index, job.cluster, expected, computed)
		}
	default:
		return nil, fmt.Errorf("unsupported checksum type: %d", checksum)
	}
	return plain, nil
}

func verifyPadding(ctx context.Context, r io.ReaderAt, offset, size int64, mainKey []byte, expected HMAC) error {
	if size == 0 {
		return nil
	}
	var key headerKey
	if err := binary.Read(hkdf.New(sha256.New, mainKey, nil, []byte(PaddingKeyInfo)), binary.LittleEndian, &key); err != nil {
		return fmt.Errorf("failed to derive padding key: %w", err)
	}
	mac := hmac.New(sha256.New, key.MAC[:])
	var buf [32 << 10]byte
	for size > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := min(size, int64(len(buf)))
		if _, err := r.ReadAt(buf[:n], offset); err != nil {
			return fmt.Errorf("failed to read padding data: %w", err)
		}
		mac.Write(buf[:n])
		offset += n
		size -= n
	}
	if actual := mac.Sum(nil); !hmac.Equal(expected[:], actual) {
		return fmt.Errorf("invalid padding HMAC: %x; expected %x", actual, expected)
	}
	return nil
}

func queueDecryptSegments(ctx context.Context, r *os.File, jobs chan<- decryptSegment, mainKey []byte, clusterMAC HMAC, root RootHeader, archiveSize int64, checksumBytes uint32) error {
	entrySize := int(checksumBytes) + 8
	headersSize := entrySize * int(root.SegmentsPerCluster)
	clusterHeader := make([]byte, headersSize+32+32*int(root.SegmentsPerCluster))
	var output uint64
	for cluster := uint32(0); output < root.FileSize; cluster++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		clusterKey, material, err := clusterKeyMaterial(mainKey, cluster)
		if err != nil {
			return err
		}
		if _, err := io.ReadFull(r, clusterHeader); err != nil {
			return fmt.Errorf("failed to read cluster %d header: %w", cluster, err)
		}
		headers, macs := clusterHeader[:headersSize], clusterHeader[headersSize:]
		mac := getHMAC(material.MAC[:], headers, macs)
		if !hmac.Equal(clusterMAC[:], mac[:]) {
			return fmt.Errorf("invalid cluster #%d HMAC: %x; expected %x", cluster, clusterMAC, mac)
		}
		copy(clusterMAC[:], macs[:32])
		if err := decryptCTRInPlace(headers, material.Key[:], material.IV[:]); err != nil {
			return fmt.Errorf("failed to decrypt segment headers: %w", err)
		}
		input, err := r.Seek(0, io.SeekCurrent)
		if err != nil {
			return fmt.Errorf("failed to locate cluster data: %w", err)
		}
		prk := hkdf.Extract(sha256.New, clusterKey, nil)
		for index := uint32(0); index < root.SegmentsPerCluster; index++ {
			entry := headers[int(index)*entrySize : (int(index)+1)*entrySize]
			job := decryptSegment{cluster: cluster, index: index, clusterPRK: prk, input: input, output: int64(output)}
			job.header.DecompressedSize = binary.LittleEndian.Uint32(entry)
			job.header.CompressedSize = binary.LittleEndian.Uint32(entry[4:])
			copy(job.header.Checksum[:], entry[8:])
			copy(job.mac[:], macs[32+32*int(index):32+32*(int(index)+1)])
			expected := min(uint64(root.SegmentSize), root.FileSize-output)
			if uint64(job.header.DecompressedSize) != expected {
				return fmt.Errorf("invalid segment %d (cluster %d) size: %d; expected %d", index, cluster, job.header.DecompressedSize, expected)
			}
			compressed := int64(job.header.CompressedSize)
			if expected == 0 {
				if compressed != 0 {
					return fmt.Errorf("nonempty unused segment %d (cluster %d)", index, cluster)
				}
				continue
			}
			if compressed == 0 || compressed > int64(root.SegmentSize) || input > archiveSize || compressed > archiveSize-input {
				return fmt.Errorf("invalid compressed size for segment %d (cluster %d): %d", index, cluster, compressed)
			}
			select {
			case jobs <- job:
			case <-ctx.Done():
				return ctx.Err()
			}
			input += compressed
			output += expected
		}
		if _, err := r.Seek(input, io.SeekStart); err != nil {
			return fmt.Errorf("failed to seek to next cluster: %w", err)
		}
	}
	paddingOffset, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("failed to locate padding: %w", err)
	}
	return verifyPadding(ctx, r, paddingOffset, archiveSize-paddingOffset, mainKey, clusterMAC)
}

func decryptClusters(ctx context.Context, r *os.File, outfile *os.File, mainKey []byte, clusterMAC HMAC, root RootHeader) error {
	checksumBytes, ok := checksumSize[root.Checksum]
	if !ok {
		return fmt.Errorf("unsupported checksum type: %d", root.Checksum)
	}
	if root.FileSize > math.MaxInt64 || root.SegmentSize == 0 || root.SegmentSize > maxAEASegmentSize || root.SegmentsPerCluster == 0 || root.SegmentsPerCluster > maxAEASegmentsPerCluster {
		return fmt.Errorf("invalid AEA root dimensions")
	}
	clusterSize := uint64(root.SegmentSize) * uint64(root.SegmentsPerCluster)
	if root.FileSize > 0 && (root.FileSize-1)/clusterSize >= 1<<32 {
		return fmt.Errorf("too many AEA clusters")
	}
	info, err := r.Stat()
	if err != nil {
		return fmt.Errorf("failed to get encrypted file size: %w", err)
	}
	if root.EncyptedSize != uint64(info.Size()) {
		return fmt.Errorf("invalid encrypted file size: %d; expected %d", info.Size(), root.EncyptedSize)
	}
	if root.FileSize == 0 {
		offset, err := r.Seek(0, io.SeekCurrent)
		if err != nil {
			return err
		}
		return verifyPadding(ctx, r, offset, info.Size()-offset, mainKey, clusterMAC)
	}

	// Larger valid AppleArchive blocks may exceed the budget for one worker.
	// Limit concurrency rather than rejecting those archives.
	workerBytes := 2*uint64(root.SegmentSize) + 1 + uint64(lzfse.DecodeScratchSize())
	workers := min(runtime.GOMAXPROCS(0), maxDecryptWorkers, max(1, int(decryptMemoryBudget/workerBytes)))
	workers = int(min(uint64(workers), (root.FileSize-1)/uint64(root.SegmentSize)+1))
	group, groupCtx := errgroup.WithContext(ctx)
	jobs := make(chan decryptSegment)
	results := make(chan decryptedSegment)
	for range workers {
		group.Go(func() error {
			var decoder segmentDecoder
			done := make(chan struct{})
			for {
				select {
				case <-groupCtx.Done():
					return groupCtx.Err()
				case job, ok := <-jobs:
					if !ok {
						return nil
					}
					plain, err := decoder.decrypt(r, job, root.Compression, root.Checksum)
					if err != nil {
						return fmt.Errorf("failed to decrypt cluster #%d: %w", job.cluster, err)
					}
					select {
					case results <- decryptedSegment{data: plain, offset: job.output, done: done}:
					case <-groupCtx.Done():
						return groupCtx.Err()
					}
					select {
					case <-done:
					case <-groupCtx.Done():
						return groupCtx.Err()
					}
				}
			}
		})
	}
	group.Go(func() error {
		defer close(jobs)
		return queueDecryptSegments(groupCtx, r, jobs, mainKey, clusterMAC, root, info.Size(), checksumBytes)
	})
	group.Go(func() error {
		pending := make(map[int64]decryptedSegment, workers)
		var next int64
		for next < int64(root.FileSize) {
			select {
			case <-groupCtx.Done():
				return groupCtx.Err()
			case result := <-results:
				pending[result.offset] = result
			}
			for {
				result, ok := pending[next]
				if !ok {
					break
				}
				if _, err := outfile.Write(result.data); err != nil {
					return fmt.Errorf("failed to write decompressed decrypted data to file: %w", err)
				}
				delete(pending, next)
				next += int64(len(result.data))
				select {
				case result.done <- struct{}{}:
				case <-groupCtx.Done():
					return groupCtx.Err()
				}
			}
		}
		return nil
	})
	if err := group.Wait(); err != nil {
		return err
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

	authOffset := int64(binary.Size(hdr))
	authSize := int64(hdr.AuthDataLength)
	finfo, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to get input file info: %w", err)
	}
	if finfo.Size() < authOffset+authSize+32+int64(binary.Size(encRootHeader{})) {
		return "", fmt.Errorf("truncated AEA prologue: %w", io.ErrUnexpectedEOF)
	}
	authData := io.NewSectionReader(f, authOffset, authSize)
	if _, err := f.Seek(authOffset+authSize, io.SeekStart); err != nil {
		return "", fmt.Errorf("failed to seek past auth data: %w", err)
	}

	mainSalt := make([]byte, 32)
	if _, err := io.ReadFull(f, mainSalt); err != nil {
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
	rhmac, err := getRootHeaderHMAC(rootHdrKey.MAC[:], encRootHdr.Data[:], encRootHdr.ClusterHmac, authData, hdr.AuthDataLength)
	if err != nil {
		return "", fmt.Errorf("failed to get encrypted root header HMAC: %v", err)
	}
	if !hmac.Equal(encRootHdr.Hmac[:], rhmac[:]) {
		return "", fmt.Errorf("invalid root header HMAC: %x; expected %x", encRootHdr.Hmac, rhmac)
	}
	rootHdrData, err := cryptCTR(encRootHdr.Data[:], rootHdrKey.Key[:], rootHdrKey.IV[:])
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

	finfo, err = of.Stat()
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
	var err error
	if c.B64SymKey != "" {
		c.symEncKey, err = base64.StdEncoding.DecodeString(c.B64SymKey)
		if err != nil {
			return "", fmt.Errorf("failed to decode base64 sym key: %w", err)
		}
	} else {
		metadata, err := Info(c.Input)
		if err != nil {
			return "", fmt.Errorf("failed to Decrypt AEA: %w", err)
		}
		if encKey, ok := metadata["encryption_key"]; ok {
			c.symEncKey, err = hex.DecodeString(string(encKey))
			if err != nil {
				return "", fmt.Errorf("failed to decode hex sym key: %w", err)
			}
		} else {
			c.symEncKey, err = metadata.DecryptFCS(c.PrivKeyData, c.PemDB, c.Proxy, c.Insecure)
			if err != nil {
				return "", fmt.Errorf("failed to HPKE decrypt fcs-key: %w", err)
			}
		}
		c.B64SymKey = base64.StdEncoding.EncodeToString(c.symEncKey)
	}

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
