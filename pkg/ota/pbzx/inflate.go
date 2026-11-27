package pbzx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/blacktop/ipsw/pkg/ota/lzraven/codec"
	"github.com/xi2/xz"
)

// inflate decodes queued chunks and forwards their original indices to the
// ordered writer, stopping on cancellation or the first decoding error.
func inflate(ctx context.Context, reader <-chan _Chunk, writeCh chan<- _Chunk, limit uint64) error {
	for {
		var chunk _Chunk
		var ok bool
		select {
		case <-ctx.Done():
			return ctx.Err()
		case chunk, ok = <-reader:
		}
		if !ok {
			return nil
		}
		data, err := decode(chunk, limit)
		if err != nil {
			return err
		}
		chunk.data = data
		select {
		case <-ctx.Done():
			return ctx.Err()
		case writeCh <- chunk:
		}
	}
}

// decode returns stored data unchanged or dispatches compressed data to the
// stream's codec, adding the chunk index to decoding errors.
func decode(chunk _Chunk, limit uint64) ([]byte, error) {
	if len(chunk.data) == chunk.meta {
		return chunk.data, nil
	}
	var data []byte
	var err error
	if chunk.pbzm {
		data = make([]byte, chunk.meta)
		err = codec.Decode(data, chunk.data)
	} else {
		data, err = inflateXZ(chunk.data, chunk.meta, limit)
	}
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return nil, fmt.Errorf("inflate chunk %d: %w", chunk.idx, err)
	}
	return data, nil
}

// inflateXZ bounds the XZ dictionary and requires exactly the declared
// output size, rejecting both truncated output and excess decoded bytes.
func inflateXZ(data []byte, size int, limit uint64) ([]byte, error) {
	rd, err := xz.NewReader(bytes.NewReader(data), uint32(limit))
	if err != nil {
		return nil, err
	}
	rd.Multistream(false)
	buf := make([]byte, size+1)
	n, err := io.ReadFull(rd, buf)
	if n == size && errors.Is(err, io.ErrUnexpectedEOF) {
		return buf[:size], nil
	}
	if err == nil {
		return nil, fmt.Errorf("XZ output exceeds declared size %d", size)
	}
	return nil, err
}
