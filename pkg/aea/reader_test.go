package aea

import (
	"bytes"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

type countingSource struct {
	io.ReaderAt
	bytes int64
}

func (c *countingSource) ReadAt(p []byte, off int64) (int, error) {
	n, e := c.ReaderAt.ReadAt(p, off)
	c.bytes += int64(n)
	return n, e
}
func TestReaderSparseAuthenticatedReads(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "payload")
	plain := make([]byte, 4*segmentSize+17)
	rand.New(rand.NewSource(42)).Read(plain)
	if err := os.WriteFile(input, plain, 0600); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{7}, 32)
	if err := Encrypt(input, &EncryptConfig{Output: dir, SymmetricKey: key}); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(input + ".aea")
	if err != nil {
		t.Fatal(err)
	}
	source := &countingSource{ReaderAt: bytes.NewReader(encoded)}
	r, err := NewReader(source, int64(len(encoded)), key)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 64)
	offset := int64(2*segmentSize + 5)
	if _, err := r.ReadAt(data, offset); err != nil || !bytes.Equal(data, plain[offset:offset+64]) {
		t.Fatalf("random read: %v", err)
	}
	if source.bytes > int64(len(encoded))/2 {
		t.Fatalf("not sparse: read %d of %d", source.bytes, len(encoded))
	}
	before := source.bytes
	if _, err := r.ReadAt(data, offset); err != nil {
		t.Fatal(err)
	}
	if before != source.bytes {
		t.Fatal("segment cache missed")
	}
	if _, err := r.ReadAt(data, int64(segmentSize-16)); err != nil || !bytes.Equal(data, plain[segmentSize-16:segmentSize+48]) {
		t.Fatal("cross-segment read", err)
	}
	if n, err := r.ReadAt(data, int64(len(plain)-5)); n != 5 || err != io.EOF {
		t.Fatalf("EOF: %d %v", n, err)
	}
	damaged := bytes.Clone(encoded)
	damaged[r.segments[2].input] ^= 1
	bad, err := NewReader(bytes.NewReader(damaged), int64(len(damaged)), key)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := bytes.Repeat([]byte{0xaa}, 10)
	if n, err := bad.ReadAt(sentinel, int64(2*segmentSize)); n != 0 || err == nil || !bytes.Equal(sentinel, bytes.Repeat([]byte{0xaa}, 10)) {
		t.Fatal("returned unauthenticated plaintext")
	}
	damaged = bytes.Clone(encoded)
	damaged[44+12] ^= 1
	if _, err := NewReader(bytes.NewReader(damaged), int64(len(damaged)), key); err == nil {
		t.Fatal("accepted modified root")
	}
	damaged = bytes.Clone(encoded)
	damaged[44+112+1] ^= 1
	if _, err := NewReader(bytes.NewReader(damaged), int64(len(damaged)), key); err == nil {
		t.Fatal("accepted modified cluster header")
	}
}
