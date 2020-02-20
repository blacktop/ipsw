package buffer

import (
	"errors"
	"io"
)

// ReadWriteBuffer is a simple type that implements io.WriterAt on an in-memory buffer.
// The zero value of this type is an empty buffer ready to use.
type ReadWriteBuffer struct {
	d []byte
	i int64 // current reading index
	m int
}

// NewReadWriteBuffer creates and returns a new ReadWriteBuffer with the given initial size and
// maximum. If maximum is <= 0 it is unlimited.
func NewReadWriteBuffer(size, max int) *ReadWriteBuffer {
	if max < size && max >= 0 {
		max = size
	}
	return &ReadWriteBuffer{make([]byte, size), 0, max}
}

// Reset resets the Reader to be reading from b.
func (rw *ReadWriteBuffer) Reset(b []byte) {
	*rw = ReadWriteBuffer{b, 0, rw.m}
}

// Len returns the number of bytes of the unread portion of the
// slice.
func (rw *ReadWriteBuffer) Len() int {
	if rw.i >= int64(len(rw.d)) {
		return 0
	}
	return int(int64(len(rw.d)) - rw.i)
}

// Size returns the original length of the underlying byte slice.
// Size is the number of bytes available for reading via ReadAt.
// The returned value is always the same and is not affected by calls
// to any other method.
func (rw *ReadWriteBuffer) Size() int64 { return int64(len(rw.d)) }

// SetMax sets the maximum capacity of the ReadWriteBuffer. If the provided maximum is lower
// than the current capacity but greater than 0 it is set to the current capacity, if
// less than or equal to zero it is unlimited..
func (rw *ReadWriteBuffer) SetMax(max int) {
	if max < len(rw.d) && max >= 0 {
		max = len(rw.d)
	}
	rw.m = max
}

// Bytes returns the ReadWriteBuffer's underlying data. This value will remain valid so long
// as no other methods are called on the ReadWriteBuffer.
func (rw *ReadWriteBuffer) Bytes() []byte {
	return rw.d
}

// Shape returns the current ReadWriteBuffer size and its maximum if one was provided.
func (rw *ReadWriteBuffer) Shape() (int, int) {
	return len(rw.d), rw.m
}

// WriteAt implements the io.WriterAt interface.
func (rw *ReadWriteBuffer) WriteAt(dat []byte, off int64) (int, error) {
	if int(off) < 0 {
		return 0, errors.New("buffer.ReadWriteBuffer.ReadAt: negative offset")
	}
	if int(off)+len(dat) >= rw.m && rw.m > 0 {
		return 0, errors.New("buffer.ReadWriteBuffer.ReadAt: offset out of range")
	}
	// Check fast path extension
	if int(off) == len(rw.d) {
		rw.d = append(rw.d, dat...)
		return len(dat), nil
	}
	// Check slower path extension
	if int(off)+len(dat) >= len(rw.d) {
		nd := make([]byte, int(off)+len(dat))
		copy(nd, rw.d)
		rw.d = nd
	}
	// Once no extension is needed just copy bytes into place.
	copy(rw.d[int(off):], dat)
	return len(dat), nil
}

// Read implements the io.Reader interface.
func (rw *ReadWriteBuffer) Read(b []byte) (n int, err error) {
	if rw.i >= int64(len(rw.d)) {
		return 0, io.EOF
	}
	n = copy(b, rw.d[rw.i:])
	rw.i += int64(n)
	return
}

// ReadAt implements the io.ReaderAt interface.
func (rw *ReadWriteBuffer) ReadAt(b []byte, off int64) (n int, err error) {
	// cannot modify state - see io.ReaderAt
	if off < 0 {
		return 0, errors.New("buffer.ReadWriteBuffer.ReadAt: negative offset")
	}
	if off >= int64(len(rw.d)) {
		return 0, io.EOF
	}
	n = copy(b, rw.d[off:])
	if n < len(b) {
		err = io.EOF
	}
	return
}

// Seek implements the io.Seeker interface.
func (rw *ReadWriteBuffer) Seek(offset int64, whence int) (int64, error) {
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = rw.i + offset
	case io.SeekEnd:
		abs = int64(len(rw.d)) + offset
	default:
		return 0, errors.New("buffer.ReadWriteBuffer.Seek: invalid whence")
	}
	if abs < 0 {
		return 0, errors.New("buffer.ReadWriteBuffer.Seek: negative position")
	}
	rw.i = abs
	return abs, nil
}
