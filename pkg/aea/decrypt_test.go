package aea

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/blacktop/lzfse-cgo"
	"golang.org/x/crypto/hkdf"
)

func TestDecryptAuthData(t *testing.T) {
	key := bytes.Repeat([]byte{0x5a}, 32)
	payload := []byte("synthetic payload\n")
	for _, tc := range []struct {
		name     string
		auth     []byte
		implicit bool
	}{
		{"raw", []byte{1}, false},
		{"large_raw", bytes.Repeat([]byte{0xa5}, 16<<20+1), false},
		{"explicit_key_wins", metadataEntry("encryption_key", strings.Repeat("00", 32)), false},
		{"embedded_key", metadataEntry("encryption_key", hex.EncodeToString(key)), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			in := filepath.Join(dir, "synthetic.bin")
			if err := os.WriteFile(in, payload, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := Encrypt(in, &EncryptConfig{Output: dir, SymmetricKey: key, AuthData: tc.auth}); err != nil {
				t.Fatal(err)
			}
			archive := in + ".aea"
			out := filepath.Join(dir, "decoded.bin")
			if _, err := decrypt(archive, out, key); err != nil {
				t.Fatal(err)
			}
			if got, err := os.ReadFile(out); err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("Go decoder plaintext differs: %v", err)
			}
			conf := &DecryptConfig{Input: archive, Output: dir}
			if !tc.implicit {
				conf.B64SymKey = base64.StdEncoding.EncodeToString(key)
			}
			decoded, err := Decrypt(conf)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := os.ReadFile(decoded); err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("public decoder plaintext differs: %v", err)
			}
		})
	}
}

func TestDecryptRejectsModifiedAuthData(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{0x5a}, 32)
	in := filepath.Join(dir, "synthetic.bin")
	if err := os.WriteFile(in, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Encrypt(in, &EncryptConfig{Output: dir, SymmetricKey: key, AuthData: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	archive := in + ".aea"
	f, err := os.OpenFile(archive, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte{2}, int64(binary.Size(Header{}))); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "decoded.bin")
	if _, err := decrypt(archive, out, key); err == nil || !strings.Contains(err.Error(), "root header HMAC") {
		t.Fatalf("modified auth data was not rejected: %v", err)
	}
	if runtime.GOOS == "darwin" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := exec.CommandContext(ctx, aeaBinPath, "decrypt", "-i", archive, "-o", out,
			"-key-value", "base64:"+base64.StdEncoding.EncodeToString(key)).Run(); err == nil {
			t.Fatal("native decoder accepted modified auth data")
		}
	}
}

func TestDecryptTruncatedPrologue(t *testing.T) {
	var data bytes.Buffer
	if err := binary.Write(&data, binary.LittleEndian, Header{
		Magic: [4]byte{'A', 'E', 'A', '1'}, ProfileAndScryptStrength: uint32(SymmetricEncryption), AuthDataLength: math.MaxUint32,
	}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	in := filepath.Join(dir, "synthetic.aea")
	if err := os.WriteFile(in, data.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := decrypt(in, filepath.Join(dir, "decoded.bin"), make([]byte, 32)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptNativeChecksums(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("native AEA is only available on macOS")
	}
	key := bytes.Repeat([]byte{0x5a}, 32)
	for _, tc := range []struct{ compression, checksum string }{
		{"none", "none"}, {"lzfse", "murmur64"}, {"zlib", "sha256"}, {"lzbitmap", "sha256"},
	} {
		t.Run(tc.compression+"_"+tc.checksum, func(t *testing.T) {
			dir := t.TempDir()
			in, archive, out := filepath.Join(dir, "input"), filepath.Join(dir, "input.aea"), filepath.Join(dir, "output")
			payload := bytes.Repeat([]byte("synthetic archive data\n"), 4097)
			if err := os.WriteFile(in, payload, 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			result, err := exec.CommandContext(ctx, aeaBinPath, "encrypt", "-i", in, "-o", archive,
				"-profile", "1", "-a", tc.compression, "-checksum", tc.checksum, "-padding", "1m", "-t", "2",
				"-key-value", "base64:"+base64.StdEncoding.EncodeToString(key)).CombinedOutput()
			if err != nil {
				t.Fatalf("native encryption: %v: %s", err, result)
			}
			if _, err := decrypt(archive, out, key); err != nil {
				t.Fatal(err)
			}
			if got, err := os.ReadFile(out); err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("plaintext differs: %v", err)
			}
			if tc.compression == "none" {
				f, err := os.OpenFile(archive, os.O_RDWR, 0)
				if err != nil {
					t.Fatal(err)
				}
				info, err := f.Stat()
				if err != nil {
					t.Fatal(err)
				}
				var last [1]byte
				if _, err := f.ReadAt(last[:], info.Size()-1); err != nil {
					t.Fatal(err)
				}
				last[0] ^= 1
				if _, err := f.WriteAt(last[:], info.Size()-1); err != nil {
					t.Fatal(err)
				}
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err := decrypt(archive, out, key); err == nil || !strings.Contains(err.Error(), "padding HMAC") {
					t.Fatalf("modified padding was not rejected: %v", err)
				}
			}
		})
	}
}

func encryptedTestSegment(t *testing.T, encoded []byte, decodedSize uint32) ([]byte, decryptSegment) {
	t.Helper()
	prk := hkdf.Extract(sha256.New, bytes.Repeat([]byte{0x5a}, 32), nil)
	var key headerKey
	if err := binary.Read(hkdf.Expand(sha256.New, prk, binary.LittleEndian.AppendUint32([]byte(SegmentKeyInfo), 0)), binary.LittleEndian, &key); err != nil {
		t.Fatal(err)
	}
	data, err := cryptCTR(encoded, key.Key[:], key.IV[:])
	if err != nil {
		t.Fatal(err)
	}
	job := decryptSegment{
		header: SegmentHeader{CompressedSize: uint32(len(data)), DecompressedSize: decodedSize},
		mac:    getHMAC(key.MAC[:], data, nil), clusterPRK: prk,
	}
	return data, job
}

func TestDecryptRawSegmentChecksum(t *testing.T) {
	plain := []byte("synthetic raw segment")
	data, job := encryptedTestSegment(t, plain, uint32(len(plain)))
	var decoder segmentDecoder
	if _, err := decoder.decrypt(bytes.NewReader(data), job, LZFSE, Sha256); err == nil || !strings.Contains(err.Error(), "SHA256 checksum") {
		t.Fatalf("invalid raw-segment checksum was not rejected: %v", err)
	}
}

func TestDecryptRejectsWrongDecodedLength(t *testing.T) {
	for _, tc := range []struct {
		name        string
		compression compressionType
		encoded     []byte
		decodedSize uint32
	}{
		{"lzbitmap_short", LZBITMAP, []byte{'Z', 'B', 'M', 9, 6, 0, 0, 0, 0, 0}, 100},
		{"lzfse_long", LZFSE, lzfse.EncodeBuffer(bytes.Repeat([]byte{0xa5}, 1024)), 512},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, job := encryptedTestSegment(t, tc.encoded, tc.decodedSize)
			decoder := segmentDecoder{decoded: bytes.Repeat([]byte{0x5a}, 2048)}
			if _, err := decoder.decrypt(bytes.NewReader(data), job, tc.compression, None); err == nil {
				t.Fatal("accepted incorrect decoded length")
			}
		})
	}
}

func TestMurmur64(t *testing.T) {
	// Checksum emitted by /usr/bin/aea -checksum murmur64.
	payload := bytes.Repeat([]byte("synthetic archive data\n"), 4097)
	if got := murmur64(payload); got != 0xd512fdb49149a3af {
		t.Fatalf("MurmurHash2-64 = %016x", got)
	}
}

func TestDecryptRejectsInvalidDimensions(t *testing.T) {
	dir := t.TempDir()
	in, err := os.Create(filepath.Join(dir, "input.aea"))
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.Create(filepath.Join(dir, "output"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	for _, root := range []RootHeader{
		{FileSize: math.MaxUint64, SegmentSize: segmentSize, SegmentsPerCluster: segmentsPerCluster, Checksum: Sha256},
		{FileSize: 1, SegmentsPerCluster: segmentsPerCluster, Checksum: Sha256},
		{FileSize: 1, SegmentSize: maxAEASegmentSize + 1, SegmentsPerCluster: segmentsPerCluster, Checksum: Sha256},
		{FileSize: 1, SegmentSize: segmentSize, SegmentsPerCluster: maxAEASegmentsPerCluster + 1, Checksum: Sha256},
	} {
		if err := decryptClusters(context.Background(), in, out, make([]byte, 32), HMAC{}, root); err == nil {
			t.Fatal("accepted invalid root dimensions")
		}
	}
	if info, err := out.Stat(); err != nil || info.Size() != 0 {
		t.Fatalf("invalid dimensions changed output: %v", err)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	const size = 128 << 20
	for _, compressed := range []bool{false, true} {
		name := "raw"
		if compressed {
			name = "lzfse"
		}
		b.Run(name, func(b *testing.B) {
			dir := b.TempDir()
			in := filepath.Join(dir, "synthetic.bin")
			f, err := os.Create(in)
			if err != nil {
				b.Fatal(err)
			}
			data := make([]byte, segmentSize)
			if _, err := rand.New(rand.NewSource(1)).Read(data); err != nil {
				b.Fatal(err)
			}
			if compressed {
				for i := range data {
					if i%4096 >= 512 {
						data[i] = byte(i % 251)
					}
				}
			}
			want := sha256.New()
			for written := 0; written < size; written += len(data) {
				if _, err := f.Write(data); err != nil {
					b.Fatal(err)
				}
				want.Write(data)
			}
			if err := f.Close(); err != nil {
				b.Fatal(err)
			}
			key := bytes.Repeat([]byte{0x5a}, 32)
			if err := Encrypt(in, &EncryptConfig{Output: dir, SymmetricKey: key}); err != nil {
				b.Fatal(err)
			}
			if err := os.Remove(in); err != nil {
				b.Fatal(err)
			}
			archive := in + ".aea"
			for _, native := range []bool{false, true} {
				implementation := "go"
				if native {
					implementation = "native"
				}
				b.Run(implementation, func(b *testing.B) {
					if native && runtime.GOOS != "darwin" {
						b.Skip("native AEA is only available on macOS")
					}
					out := filepath.Join(dir, implementation+".out")
					b.SetBytes(size)
					b.ReportAllocs()
					for b.Loop() {
						if native {
							ctx, cancel := context.WithTimeout(b.Context(), 2*time.Minute)
							result, err := exec.CommandContext(ctx, aeaBinPath, "decrypt", "-i", archive, "-o", out,
								"-key-value", "base64:"+base64.StdEncoding.EncodeToString(key)).CombinedOutput()
							cancel()
							if err != nil {
								b.Fatalf("native decryption: %v: %s", err, result)
							}
						} else if _, err := decrypt(archive, out, key); err != nil {
							b.Fatal(err)
						}
					}
					if !bytes.Equal(fileDigest(b, out), want.Sum(nil)) {
						b.Fatal("plaintext differs")
					}
				})
			}
		})
	}
}
