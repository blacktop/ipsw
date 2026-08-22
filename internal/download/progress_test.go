package download

import (
	"io"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/vbauerster/mpb/v8"
)

func newTestProgressReporter(total int64) *progressReporter {
	r := newProgressReporter()
	r.p = mpb.New(mpb.WithOutput(io.Discard), mpb.WithRefreshRate(time.Millisecond))
	r.total = r.p.AddBar(total)
	return r
}

func TestProgressReporterIgnoresResizeAfterChunkDone(t *testing.T) {
	r := newTestProgressReporter(100)
	r.ChunkStart(1, 0, 100, 0)
	r.ChunkDone(1)
	r.ChunkResize(1, 75)

	done := make(chan struct{})
	go func() {
		r.Done(nil)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Done() blocked after resizing a completed chunk")
	}
}

func TestProgressReporterPreservesReportedProgressAcrossResize(t *testing.T) {
	tests := []struct {
		name     string
		reported int
	}{
		{name: "partially reported", reported: 25},
		{name: "mostly reported", reported: 60},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newTestProgressReporter(100)
			r.ChunkStart(0, 0, 100, 0)
			r.ChunkProgress(0, tt.reported, time.Millisecond)
			victim := r.bars[0].bar

			r.ChunkResize(0, 75)
			r.ChunkStart(1, 75, 25, 0)
			if got := victim.Current(); got != int64(tt.reported) {
				t.Errorf("victim progress after resize = %d, want %d", got, tt.reported)
			}
			if got := r.total.Current(); got != int64(tt.reported) {
				t.Errorf("total progress after resize = %d, want %d", got, tt.reported)
			}

			r.ChunkProgress(0, 75-tt.reported, time.Millisecond)
			r.ChunkDone(0)
			r.ChunkProgress(1, 25, time.Millisecond)
			r.ChunkDone(1)
			if got := r.total.Current(); got != 100 {
				t.Errorf("final total progress = %d, want 100", got)
			}
			r.Done(nil)
		})
	}
}

func TestProgressReporterIgnoresStaleResizeLength(t *testing.T) {
	r := newTestProgressReporter(100)
	r.ChunkStart(0, 0, 100, 0)
	r.ChunkProgress(0, 25, time.Millisecond)

	r.ChunkResize(0, 75)
	r.ChunkResize(0, 50)
	r.ChunkResize(0, 75)

	chunk := r.bars[0]
	if got := chunk.length; got != 50 {
		t.Errorf("chunk length after stale resize = %d, want 50", got)
	}
	if got := chunk.bar.Current(); got != 25 {
		t.Errorf("chunk progress after stale resize = %d, want 25", got)
	}
	if got := r.total.Current(); got != 25 {
		t.Errorf("total progress after stale resize = %d, want 25", got)
	}

	r.ChunkDone(0)
	r.Done(nil)
}

func TestProgressReporterRollsBackSingleStreamRetry(t *testing.T) {
	r := newTestProgressReporter(100)
	r.ChunkStart(0, 0, 100, 0)
	r.ChunkProgress(0, 40, time.Millisecond)
	bar := r.bars[0].bar

	r.ChunkRestart(0)
	if got := bar.Current(); got != 0 {
		t.Errorf("chunk progress after retry = %d, want 0", got)
	}
	if got := r.total.Current(); got != 0 {
		t.Errorf("total progress after retry = %d, want 0", got)
	}

	r.ChunkProgress(0, 100, time.Millisecond)
	r.ChunkDone(0)
	r.Done(nil)
}

func TestProgressReporterSerializesConcurrentAggregateProgress(t *testing.T) {
	const (
		chunks  = 16
		updates = 128
		total   = chunks * updates
	)
	r := newTestProgressReporter(total)
	for id := range chunks {
		r.ChunkStart(id, 0, updates, 0)
	}

	start := make(chan struct{})
	stop := make(chan struct{})
	regression := make(chan [2]int64, 1)
	go func() {
		var previous int64
		for {
			current := r.total.Current()
			if current < previous {
				regression <- [2]int64{previous, current}
				return
			}
			previous = current
			select {
			case <-stop:
				regression <- [2]int64{}
				return
			default:
				runtime.Gosched()
			}
		}
	}()

	var wg sync.WaitGroup
	for id := range chunks {
		wg.Go(func() {
			<-start
			for range updates {
				r.ChunkProgress(id, 1, time.Nanosecond)
				runtime.Gosched()
			}
		})
	}
	close(start)
	wg.Wait()
	close(stop)
	if got := <-regression; got != [2]int64{} {
		t.Errorf("aggregate progress regressed from %d to %d", got[0], got[1])
	}

	if got := r.total.Current(); got != total {
		t.Errorf("aggregate progress after concurrent updates = %d, want %d", got, total)
	}
	for id := range chunks {
		r.ChunkDone(id)
	}
	r.Done(nil)
}

func TestProgressReporterRetirementResizeToZeroCompletes(t *testing.T) {
	r := newTestProgressReporter(100)
	r.ChunkStart(1, 0, 50, 0)
	r.ChunkProgress(1, 10, time.Millisecond)

	r.ChunkResize(1, 0)
	if r.bars[1].bar.Completed() {
		t.Fatal("resize to zero completed the bar before ChunkDone")
	}
	r.ChunkDone(1)
	if !r.bars[1].bar.Completed() {
		t.Fatal("ChunkDone did not complete a zero-length retired bar")
	}

	done := make(chan struct{})
	go func() {
		r.Done(nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Done() blocked after retirement resized a chunk to zero")
	}
}
