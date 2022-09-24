package pbzx

import (
	"bytes"
	"context"
	"io"

	"github.com/palantir/stacktrace"
	"github.com/xi2/xz"
)

func inflate(ctx context.Context, reader <-chan _Chunk, writeCh chan<- _Chunk) error {
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
		rd, err := xz.NewReader(bytes.NewBuffer(chunk.data), 0)
		rd.Multistream(false)
		if err != nil {
			return stacktrace.Propagate(err, "inflate error")
		}
		buf := make([]byte, chunk.meta+1)
		n, err := io.ReadFull(rd, buf)
		if err != io.ErrUnexpectedEOF || n != chunk.meta {
			return stacktrace.Propagate(err, "inflate error")
		}
		chunk.data = buf[:chunk.meta]
		select {
		case <-ctx.Done():
			return ctx.Err()
		case writeCh <- chunk:
		}
	}
}
