package pbzx

import (
	"container/heap"
	"context"
	"fmt"
	"io"
)

// write restores chunk order and releases an in-flight slot only after the
// chunk is written. Missing chunks at the end are reported as truncation.
func write(
	ctx context.Context,
	writeCh <-chan _Chunk,
	dst io.Writer,
	pending <-chan struct{},
) error {
	next := 0
	write := func(c _Chunk) error {
		n, err := dst.Write(c.data)
		if err == nil && n != len(c.data) {
			err = io.ErrShortWrite
		}
		if err != nil {
			return fmt.Errorf("write error: %w", err)
		}
		next += 1
		<-pending
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
