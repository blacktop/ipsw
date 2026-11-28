package pbzx

import "io"

// Reader decodes a PBZX or PBZM stream one chunk at a time.
type Reader struct {
	stream *stream
	data   []byte
	err    error
}

// NewReader opens a sequential decoder. A zero limit selects
// DefaultMaxBlockSize. The caller owns src.
func NewReader(src io.Reader, maxBlockSize uint64) (*Reader, error) {
	s, err := openStream(src, maxBlockSize)
	if err != nil {
		return nil, err
	}
	return &Reader{stream: s}, nil
}

// Read decodes chunks on demand and releases each buffer when consumed.
// A terminal error is retained for subsequent reads and releases the source.
func (r *Reader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.err != nil {
		return 0, r.err
	}
	for len(r.data) == 0 {
		chunk, err := r.stream.next()
		if err == nil {
			r.data, err = decode(chunk, r.stream.limit)
		}
		if err != nil {
			r.stream = nil
			r.err = err
			return 0, err
		}
	}
	n := copy(p, r.data)
	if n == len(r.data) {
		r.data = nil
	} else {
		r.data = r.data[n:]
	}
	return n, nil
}
