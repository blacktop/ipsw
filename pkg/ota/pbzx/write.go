package pbzx

import (
	"container/heap"
	"context"
	"io"

	"github.com/palantir/stacktrace"
)

func write(ctx context.Context, writeCh <-chan _Chunk, dst io.Writer) error {
	next := 0
	write := func(c _Chunk) error {
		if _, err := dst.Write(c.data); err != nil {
			return stacktrace.Propagate(err, "write error")
		}
		next += 1
		return nil
	}

	h := make(_Heap, 0, 4)
	for {
		var chunk _Chunk
		var ok bool
		select {
		case <-ctx.Done():
			return ctx.Err()
		case chunk, ok = <-writeCh:
		}
		if !ok {
			if len(h) == 0 {
				return nil
			} else {
				return io.ErrUnexpectedEOF
			}
		}
		if chunk.idx == next {
			if err := write(chunk); err != nil {
				return err
			}

			// drain existing chunks
			for len(h) > 0 && h[0].idx == next {
				if err := write(heap.Pop(&h).(_Chunk)); err != nil {
					return err
				}
			}
		} else {
			heap.Push(&h, chunk)
		}
	}
}
