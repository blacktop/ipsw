package pbzx

import (
	"context"
	"io"
	"runtime"
	"sync"
)

// Extract writes the decoded contents of a PBZX or PBZM stream to dst.
func Extract(ctx context.Context, src io.Reader, dst io.Writer, numWorker int) error {
	return ExtractWithLimit(ctx, src, dst, numWorker, DefaultMaxBlockSize)
}

// ExtractWithLimit is like Extract with the given limit on encoded and
// decoded chunk sizes and the XZ dictionary. Zero selects the default.
func ExtractWithLimit(
	ctx context.Context,
	src io.Reader,
	dst io.Writer,
	numWorker int,
	maxBlockSize uint64,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s, err := openStream(src, maxBlockSize)
	if err != nil {
		return err
	}
	if numWorker == 0 {
		numWorker = runtime.NumCPU()
	}
	numWorker = max(numWorker, 1)
	// Hold a slot until each chunk has been written in order.
	pending := make(chan struct{}, numWorker)
	errCh := make(chan error, 1)
	inflateCh := make(chan _Chunk, 1)
	writeCh := make(chan _Chunk, 1)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cancelIfError := func(err error) {
		if err != nil {
			select {
			case errCh <- err: // do nothing
			default: // do not block
			}
			cancel()
		}
	}

	var wg1, wg2 sync.WaitGroup

	wg1.Go(func() {
		cancelIfError(read(ctx, s, inflateCh, writeCh, pending))
	})

	wg1.Add(numWorker)
	for i := 0; i < numWorker; i += 1 {
		go func() {
			defer wg1.Done()
			cancelIfError(inflate(ctx, inflateCh, writeCh, s.limit))
		}()
	}

	wg2.Go(func() {
		cancelIfError(write(ctx, writeCh, dst, pending))
	})

	wg1.Wait()
	close(writeCh)
	wg2.Wait()

	select {
	case err := <-errCh:
		return err
	default:
		return ctx.Err()
	}
}
