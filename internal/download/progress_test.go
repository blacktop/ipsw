package download

import (
	"io"
	"runtime"
	"sync"
	"testing"
	"time"

	godl "github.com/blacktop/go-download"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
)

func newTestProgressReporter(total int64) *progressReporter {
	r := newProgressReporter()
	r.p = mpb.New(mpb.WithOutput(io.Discard), mpb.WithRefreshRate(time.Millisecond))
	r.total = r.p.AddBar(total)
	return r
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// newRateReporter drives the real Start seeding path with a fake clock so
// rate assertions are deterministic.
func newRateReporter(t *testing.T, total, resumed int64) (*progressReporter, *fakeClock) {
	t.Helper()
	clock := &fakeClock{t: time.Unix(1000, 0)}
	r := newProgressReporter()
	r.rate.now = clock.now
	r.p = mpb.New(mpb.WithOutput(io.Discard), mpb.WithRefreshRate(time.Millisecond))
	r.Start(godl.Info{Total: total, Resumed: resumed})
	r.ChunkStart(0, 0, total, resumed)
	t.Cleanup(func() { r.ChunkDone(0); r.Done(nil) })
	return r, clock
}

// establishRate reports n bytes on either side of a one-second tick, leaving
// the window baseline at the first sample and a fresh rate of n B/s.
func establishRate(r *progressReporter, clock *fakeClock, n int) {
	r.ChunkProgress(0, n, time.Millisecond)
	clock.advance(time.Second)
	r.ChunkProgress(0, n, time.Millisecond)
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
			// exercise the render-side readers against concurrent writers
			r.aggregateSpeed(decor.Statistics{})
			r.aggregateETA(decor.Statistics{Total: total, Current: current})
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

func TestProgressReporterResumeSeedDoesNotInflateRate(t *testing.T) {
	const total, resumed = int64(20 << 30), int64(18 << 30)
	r, clock := newRateReporter(t, total, resumed)

	if got := r.total.Current(); got != resumed {
		t.Fatalf("seeded bar position = %d, want %d", got, resumed)
	}
	clock.advance(10 * time.Second)
	if got := r.rate.perSecond(); got != 0 {
		t.Errorf("rate with zero fresh bytes = %f, want 0", got)
	}
	if got := r.aggregateETA(decor.Statistics{Total: total, Current: resumed}); got != "--" {
		t.Errorf("ETA with zero fresh bytes = %q, want --", got)
	}
}

func TestProgressReporterRateIndependentOfResumeSeed(t *testing.T) {
	const total = int64(1 << 20)
	rateFor := func(resumed int64) float64 {
		r, clock := newRateReporter(t, total, resumed)
		establishRate(r, clock, 1000)
		return r.rate.perSecond()
	}
	cold, warm := rateFor(0), rateFor(total/2)
	if cold != warm {
		t.Errorf("rate depends on resume seed: cold=%f resumed=%f", cold, warm)
	}
	// the window baseline is the first sample, so only the second write counts
	if cold != 1000 {
		t.Errorf("fresh rate = %f B/s, want 1000", cold)
	}
}

func TestProgressReporterETAUsesRemainingBytesAndFreshRate(t *testing.T) {
	const total, resumed = int64(1 << 20), int64(1 << 19)
	r, clock := newRateReporter(t, total, resumed)
	establishRate(r, clock, 1000) // fresh rate: 1000 B/s

	current := resumed + 2000
	eta := func(total, current int64) string {
		return r.aggregateETA(decor.Statistics{Total: total, Current: current})
	}
	if got := eta(current+5000, current); got != "5s" {
		t.Errorf("ETA = %q, want 5s (remaining 5000 B at 1000 B/s)", got)
	}
	if got := eta(current, current); got != "0s" {
		t.Errorf("ETA with nothing remaining = %q, want 0s", got)
	}
	const hundredHoursAtRate = int64(100*time.Hour/time.Second) * 1000
	if got := eta(current+hundredHoursAtRate, current); got != "100h0m0s" {
		t.Errorf("representable long ETA = %q, want 100h0m0s", got)
	}
	// beyond time.Duration the ETA stays honest instead of overflowing
	if got := eta(current+(1<<62), current); got != "--" {
		t.Errorf("ETA beyond time.Duration = %q, want --", got)
	}
}

func TestProgressReporterRateWindowRollsUnderHighFrequencyEvents(t *testing.T) {
	r, clock := newRateReporter(t, 1<<30, 0)

	// events every 50ms — faster than the 100ms sampling interval. A frozen
	// baseline would report the 5,500 B/s whole-transfer average.
	const tick = 50 * time.Millisecond
	step := func(n, ticks int) {
		for range ticks {
			r.ChunkProgress(0, n, time.Millisecond)
			clock.advance(tick)
		}
	}
	step(500, 200) // 10s fast phase: 10,000 B/s
	step(50, 200)  // 10s slow phase: 1,000 B/s

	if got := r.rate.perSecond(); got < 900 || got > 1100 {
		t.Errorf("rate after sustained slowdown = %f B/s, want ~1000 (rolling window)", got)
	}
	r.rate.mu.Lock()
	samples := len(r.rate.samples)
	r.rate.mu.Unlock()
	if limit := int(rateWindow/rateSampleEvery) + 2; samples > limit {
		t.Errorf("retained samples = %d, want <= %d (window not pruned)", samples, limit)
	}
}

func TestProgressReporterResizeDoesNotAlterAggregateRate(t *testing.T) {
	r, clock := newRateReporter(t, 1<<20, 0)
	establishRate(r, clock, 1000)

	before := r.rate.perSecond()
	r.ChunkResize(0, 1<<19)
	if got := r.rate.perSecond(); got != before {
		t.Errorf("rate after resize = %f, want unchanged %f", got, before)
	}
}

func TestProgressReporterRestartResetsRateBaseline(t *testing.T) {
	r, clock := newRateReporter(t, 1<<20, 0)
	establishRate(r, clock, 8000)
	if got := r.rate.perSecond(); got != 8000 {
		t.Fatalf("pre-restart rate = %f, want 8000", got)
	}

	r.ChunkRestart(0)
	if got := r.rate.perSecond(); got != 0 {
		t.Errorf("rate right after restart = %f, want 0", got)
	}

	establishRate(r, clock, 500)
	if got := r.rate.perSecond(); got != 500 {
		t.Errorf("post-restart rate = %f, want 500 from fresh bytes only", got)
	}
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
