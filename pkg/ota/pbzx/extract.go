package pbzx

import (
	"context"
	"io"
	"runtime"
	"sync"
)

func Extract(ctx context.Context, src io.Reader, dst io.Writer, numWorker int) error {
	errCh := make(chan error, 1)
	inflateCh := make(chan _Chunk, 1)
	writeCh := make(chan _Chunk, 1)

	ctx, cancel := context.WithCancel(ctx)
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
		cancelIfError(read(ctx, src, inflateCh, writeCh))
	})

	if numWorker == 0 {
		numWorker = runtime.NumCPU()
	}
	if numWorker <= 0 {
		numWorker = 1
	}

	wg1.Add(numWorker)
	for i := 0; i < numWorker; i += 1 {
		go func() {
			defer wg1.Done()
			cancelIfError(inflate(ctx, inflateCh, writeCh))
		}()
	}

	wg2.Go(func() {
		cancelIfError(write(ctx, writeCh, dst))
	})

	wg1.Wait()
	close(writeCh)
	wg2.Wait()

	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}
