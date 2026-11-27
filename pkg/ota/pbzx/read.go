package pbzx

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

type stream struct {
	src              io.Reader
	limit, blockSize uint64
	pbzm             bool
	idx              int
}

// openStream validates the PBZX or PBZM header and establishes allocation
// limits before any chunk payload is read. A zero limit selects the default.
func openStream(src io.Reader, limit uint64) (*stream, error) {
	if limit == 0 {
		limit = DefaultMaxBlockSize
	}
	if limit >= math.MaxInt || limit > math.MaxUint32 {
		return nil, fmt.Errorf("pbzx: invalid block size limit %d", limit)
	}
	var hdr [12]byte
	if _, err := io.ReadFull(src, hdr[:4]); err != nil {
		return nil, fmt.Errorf("read error: %w", err)
	}
	magic := string(hdr[:4])
	if magic != Magic && magic != MagicPBZM {
		return nil, fmt.Errorf("pbzx magic mismatch")
	}
	if _, err := io.ReadFull(src, hdr[4:]); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, fmt.Errorf("read error: %w", err)
	}
	blockSize := binary.BigEndian.Uint64(hdr[4:])
	if blockSize > limit || (magic == MagicPBZM && blockSize == 0) {
		return nil, fmt.Errorf("pbzx: invalid block size %d", blockSize)
	}
	return &stream{src: src, blockSize: blockSize, limit: limit, pbzm: magic == MagicPBZM}, nil
}

// next reads one indexed chunk after checking its declared sizes against
// the stream limits. EOF is valid only between complete chunk records.
func (s *stream) next() (_Chunk, error) {
	var header [16]byte
	if _, err := io.ReadFull(s.src, header[:]); err != nil {
		if err == io.EOF {
			return _Chunk{}, err
		}
		return _Chunk{}, fmt.Errorf("read error: %w", err)
	}
	inflateSize := binary.BigEndian.Uint64(header[:8])
	deflateSize := binary.BigEndian.Uint64(header[8:])
	if inflateSize > s.limit || deflateSize > inflateSize ||
		(s.pbzm && (inflateSize > s.blockSize || deflateSize == 0)) {
		return _Chunk{}, fmt.Errorf(
			"pbzx: invalid chunk %d sizes (%d encoded, %d decoded)",
			s.idx,
			deflateSize,
			inflateSize,
		)
	}
	chunk := _Chunk{
		idx:  s.idx,
		meta: int(inflateSize),
		data: make([]byte, deflateSize),
		pbzm: s.pbzm,
	}
	if _, err := io.ReadFull(s.src, chunk.data); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return _Chunk{}, fmt.Errorf("read error: %w", err)
	}
	s.idx++
	return chunk, nil
}

// read limits chunks in flight and routes compressed chunks to the decoder
// workers while sending stored chunks directly to the ordered writer.
func read(
	ctx context.Context,
	s *stream,
	inflateCh, writeCh chan<- _Chunk,
	pending chan<- struct{},
) error {
	defer close(inflateCh)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case pending <- struct{}{}:
		}
		chunk, err := s.next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target := writeCh
		if len(chunk.data) < chunk.meta {
			target = inflateCh
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case target <- chunk:
		}
	}
}
