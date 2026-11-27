package pbzx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/blacktop/ipsw/pkg/ota/lzraven/codec"
)

// DefaultPBZMBlockSize is the decoded chunk size used when none is supplied.
const DefaultPBZMBlockSize = 1 << 20

// PBZMWriter writes a PBZM stream. Close flushes the stream without closing
// its destination.
type PBZMWriter struct {
	dst    io.Writer
	data   []byte
	closed bool
	err    error
}

// NewPBZMWriter writes the stream header and returns a writer. A zero block
// size selects DefaultPBZMBlockSize.
func NewPBZMWriter(dst io.Writer, blockSize uint64) (*PBZMWriter, error) {
	if blockSize == 0 {
		blockSize = DefaultPBZMBlockSize
	}
	if blockSize > DefaultMaxBlockSize {
		return nil, fmt.Errorf("pbzx: block size %d exceeds limit", blockSize)
	}
	var header [12]byte
	copy(header[:], MagicPBZM)
	binary.BigEndian.PutUint64(header[4:], blockSize)
	if err := writeBlock(dst, header[:]); err != nil {
		return nil, err
	}
	return &PBZMWriter{dst: dst, data: make([]byte, 0, blockSize)}, nil
}

// Write buffers input into chunks and emits each full chunk. A flush failure
// is retained for subsequent calls and releases the destination and buffer.
func (w *PBZMWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, errors.New("pbzx: write after close")
	}
	written := 0
	for len(p) != 0 && w.err == nil {
		n := min(len(p), cap(w.data)-len(w.data))
		w.data = append(w.data, p[:n]...)
		p = p[n:]
		written += n
		if len(w.data) == cap(w.data) {
			w.err = w.flush()
			if w.err != nil {
				w.dst = nil
				w.data = nil
			}
		}
	}
	return written, w.err
}

// Close flushes any partial chunk and releases buffered data and the
// destination reference. It does not close the destination; repeated calls
// return the same final error.
func (w *PBZMWriter) Close() error {
	if !w.closed {
		w.closed = true
		if w.err == nil && len(w.data) != 0 {
			w.err = w.flush()
		}
		w.dst = nil
		w.data = nil
	}
	return w.err
}

// flush writes the buffered chunk, storing it uncompressed when encoding
// would not reduce its size. The buffer is reset only after a successful write.
func (w *PBZMWriter) flush() error {
	encoded, err := codec.Encode(w.data)
	if err != nil {
		return fmt.Errorf("encode PBZM chunk: %w", err)
	}
	if len(encoded) >= len(w.data) {
		encoded = w.data
	}
	var header [16]byte
	binary.BigEndian.PutUint64(header[:8], uint64(len(w.data)))
	binary.BigEndian.PutUint64(header[8:], uint64(len(encoded)))
	if err := writeBlock(w.dst, header[:]); err != nil {
		return err
	}
	if err := writeBlock(w.dst, encoded); err != nil {
		return err
	}
	w.data = w.data[:0]
	return nil
}
