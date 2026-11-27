//go:build cgo

package pbzx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// TestPBZMWriter checks compressed and stored chunks in the same stream,
// round-trip output, and propagation of a destination short write through
// Close.
func TestPBZMWriter(t *testing.T) {
	const blockSize = 4096
	plain := append(make([]byte, blockSize), "raw"...)
	var wire bytes.Buffer
	w, err := NewPBZMWriter(&wire, blockSize)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	frame := wire.Bytes()
	encodedSize := binary.BigEndian.Uint64(frame[20:28])
	if encodedSize >= blockSize {
		t.Fatal("compressible block was stored raw")
	}
	if !bytes.HasSuffix(frame[28+encodedSize:], []byte("raw")) {
		t.Fatal("short block was not stored raw")
	}
	var decoded bytes.Buffer
	if err := Extract(t.Context(), &wire, &decoded, 2); err != nil ||
		!bytes.Equal(decoded.Bytes(), plain) {
		t.Fatalf("round trip produced %d bytes: %v", decoded.Len(), err)
	}

	w, err = NewPBZMWriter(&headerOnlyWriter{}, blockSize)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write returned %v", err)
	}
	if err := w.Close(); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("close returned %v", err)
	}
}

type headerOnlyWriter struct {
	written bool
}

// Write accepts the stream header, then simulates a destination that makes
// no further progress without reporting an error.
func (w *headerOnlyWriter) Write(p []byte) (int, error) {
	if w.written {
		return 0, nil
	}
	w.written = true
	return len(p), nil
}

// TestPBZMWriterReleasesDestinationAfterClose checks that Close flushes the
// final partial chunk and releases the destination reference.
func TestPBZMWriterReleasesDestinationAfterClose(t *testing.T) {
	var dst bytes.Buffer
	w, err := NewPBZMWriter(&dst, 8)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, "data"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(dst.Bytes(), []byte("data")) {
		t.Fatal("close did not flush the final chunk")
	}
	if w.dst != nil {
		t.Fatal("closed writer retained its destination")
	}
}

// TestPBZMWriterReleasesFailedChunk checks that a failed flush releases its
// buffers and that subsequent Write and Close calls preserve the failure.
func TestPBZMWriterReleasesFailedChunk(t *testing.T) {
	w, err := NewPBZMWriter(&headerOnlyWriter{}, 4)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := io.WriteString(w, "abcd!"); n != 4 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("failed write returned (%d, %v)", n, err)
	}
	if w.dst != nil || w.data != nil {
		t.Fatal("writer retained the destination or the failed chunk")
	}
	if n, err := io.WriteString(w, "!"); n != 0 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("subsequent write returned (%d, %v)", n, err)
	}
	if err := w.Close(); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("close returned %v", err)
	}
}
