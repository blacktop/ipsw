//go:build cgo

package pbzx

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/ulikunitz/xz"
)

// TestExtract checks ordered compressed & raw chunks using a known-good fixture
func TestExtract(t *testing.T) {
	const size = 4096
	vector, err := os.ReadFile("../lzraven/codec/testdata/apple/zeros_4k.rav")
	if err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	xw, err := xz.NewWriter(&compressed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := xw.Write(make([]byte, size)); err != nil {
		t.Fatal(err)
	}
	if err := xw.Close(); err != nil {
		t.Fatal(err)
	}
	for magic, payload := range map[string][]byte{
		Magic:     compressed.Bytes(),
		MagicPBZM: vector,
	} {
		t.Run(magic, func(t *testing.T) {
			var stream bytes.Buffer
			stream.WriteString(magic)
			if err := binary.Write(
				&stream,
				binary.BigEndian,
				[3]uint64{size, size, uint64(len(payload))},
			); err != nil {
				t.Fatal(err)
			}
			stream.Write(payload)
			if err := binary.Write(
				&stream,
				binary.BigEndian,
				[2]uint64{3, 3},
			); err != nil {
				t.Fatal(err)
			}
			stream.WriteString("raw")
			hash := sha256.New()
			if err := Extract(
				t.Context(),
				bytes.NewReader(stream.Bytes()),
				hash,
				2,
			); err != nil {
				t.Fatal(err)
			}
			if got, want := hash.Sum(
				nil,
			), sha256.Sum256(append(make([]byte, size), "raw"...)); !bytes.Equal(
				got,
				want[:],
			) {
				t.Fatalf("decoded SHA-256: got %x, want %x", got, want)
			}
			reader, err := NewReader(bytes.NewReader(stream.Bytes()), 0)
			if err != nil {
				t.Fatal(err)
			}
			pullHash := sha256.New()
			if _, err := io.Copy(pullHash, reader); err != nil ||
				!bytes.Equal(pullHash.Sum(nil), hash.Sum(nil)) {
				t.Fatalf("sequential SHA-256 = %x, %v", pullHash.Sum(nil), err)
			}
			if err := ExtractWithLimit(
				t.Context(),
				bytes.NewReader(stream.Bytes()),
				io.Discard,
				2,
				1024,
			); err == nil ||
				errors.Is(err, io.EOF) {
				t.Fatalf("block above limit: got %v", err)
			}
			if err := Extract(
				t.Context(),
				bytes.NewReader(stream.Bytes()[:30]),
				io.Discard,
				2,
			); !errors.Is(
				err,
				io.ErrUnexpectedEOF,
			) {
				t.Fatalf("truncated chunk: got %v, want unexpected EOF", err)
			}
		})
	}
}

// TestExtractExternalPBZM replays a standalone PBZM stream or a version-0
// BXDIFF50 full replacement containing one. File extensions are not used.
// Codec known-answer tests use the checked-in paired fixtures.
func TestExtractExternalPBZM(t *testing.T) {
	path := os.Getenv("PBZM_TEST_FILE")
	if path == "" {
		t.Skip("set PBZM_TEST_FILE to a PBZM stream or a BXDIFF50 replacement patch")
	}
	src, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	var magic [8]byte
	if _, err := io.ReadFull(src, magic[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	var offset int64
	var expectedSHA1 []byte
	var expectedSize uint64
	if string(magic[:]) == "BXDIFF50" {
		// Version 0 has a 60-byte header. Zero controls means that the
		// following stream replaces the whole image without a base.
		var header [60]byte
		if _, err := io.ReadFull(src, header[:]); err != nil {
			t.Fatal(err)
		}
		if binary.LittleEndian.Uint64(header[8:16]) != 0 ||
			binary.LittleEndian.Uint64(header[24:32]) != 0 {
			t.Fatal("expected a version-0 source-independent BXDIFF50 patch")
		}
		offset = int64(len(header))
		expectedSize = binary.LittleEndian.Uint64(header[16:24])
		expectedSHA1 = header[40:]
	}
	stream, err := openStream(src, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !stream.pbzm {
		t.Fatal("expected a PBZM stream")
	}
	var size int64
	compressed := 0
	for {
		chunk, err := stream.next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		size += int64(chunk.meta)
		if len(chunk.data) < chunk.meta {
			compressed++
		}
	}
	if expectedSHA1 != nil && uint64(size) != expectedSize {
		t.Fatalf("PBZM output size = %d, want patch-header size %d", size, expectedSize)
	}
	if compressed == 0 {
		t.Fatal("expected at least one compressed PBZM chunk")
	}
	if _, err := src.Seek(offset, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	parallel := sha256.New()
	imageDigest := sha1.New()
	var output io.Writer = parallel
	if expectedSHA1 != nil {
		output = io.MultiWriter(parallel, imageDigest)
	}
	if err := Extract(t.Context(), src, output, 4); err != nil {
		t.Fatal(err)
	}
	if expectedSHA1 != nil {
		if got := imageDigest.Sum(nil); !bytes.Equal(got, expectedSHA1) {
			t.Fatalf("replacement SHA-1 = %x, want %x", got, expectedSHA1)
		}
		t.Logf("verified complete replacement image SHA-1 %x", expectedSHA1)
	}
	if _, err := src.Seek(offset, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	reader, err := NewReader(src, 0)
	if err != nil {
		t.Fatal(err)
	}
	sequential := sha256.New()
	n, err := io.Copy(sequential, reader)
	if err != nil || n != size {
		t.Fatalf("decoded %d bytes, %v; want %d bytes", n, err, size)
	}
	if !bytes.Equal(parallel.Sum(nil), sequential.Sum(nil)) {
		t.Fatal("parallel and sequential output differ")
	}
	t.Logf("decoded %d bytes from %d chunks (%d compressed)", size, stream.idx, compressed)
}
