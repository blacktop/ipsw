package mpb

import (
	"io"
	"time"
)

// Reader is io.Reader wrapper, for proxy read bytes
type Reader struct {
	io.Reader
	bar *Bar
}

func (r *Reader) Read(p []byte) (int, error) {
	start := time.Now()
	n, err := r.Reader.Read(p)
	r.bar.IncrBy(n, time.Since(start))
	return n, err
}

// Close the reader when it implements io.Closer
func (r *Reader) Close() error {
	if closer, ok := r.Reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
