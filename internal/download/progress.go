package download

import (
	"fmt"
	"sync"
	"time"

	"github.com/apex/log"
	godl "github.com/blacktop/go-download"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
)

const totalBarPriority = 1 << 20

type chunkBar struct {
	bar    *mpb.Bar
	length int64
	done   bool // retain completed ids so later resize/restart events are ignored
}

// progressReporter renders go-download progress events as mpb bars: one bar
// per parallel part (created and re-sized as the scheduler splits work) plus
// an aggregate total bar. The mpb renderer starts lazily with the first bar,
// so unknown-size downloads and failed setups never spawn it.
type progressReporter struct {
	mu      sync.Mutex
	p       *mpb.Progress
	bars    map[int]*chunkBar
	counted map[int]int64
	sum     int64
	total   *mpb.Bar
}

func newProgressReporter() *progressReporter {
	return &progressReporter{
		bars:    make(map[int]*chunkBar),
		counted: make(map[int]int64),
	}
}

var (
	_ godl.Reporter       = (*progressReporter)(nil)
	_ godl.ChunkResizer   = (*progressReporter)(nil)
	_ godl.ChunkRestarter = (*progressReporter)(nil)
)

// ensureProgress lazily starts the mpb renderer. Must be called with r.mu
// held. Single-stream downloads can recover a size the probe could not, so
// ChunkStart needs this as well as Start.
func (r *progressReporter) ensureProgress() {
	if r.p == nil {
		r.p = mpb.New(
			mpb.WithWidth(60),
			mpb.WithRefreshRate(180*time.Millisecond),
		)
	}
}

func barStyle() mpb.BarStyleComposer {
	return mpb.BarStyle().Lbound("[").Filler("=").Tip(">").Padding("-").Rbound("|")
}

func (r *progressReporter) Start(info godl.Info) {
	if info.Total < 0 {
		return // unknown size: no meaningful bar to draw
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ensureProgress()
	r.total = r.p.New(info.Total,
		barStyle(),
		mpb.BarPriority(totalBarPriority),
		mpb.PrependDecorators(
			decor.CountersKibiByte("\t% .2f / % .2f"),
		),
		mpb.AppendDecorators(
			decor.OnComplete(decor.AverageETA(decor.ET_STYLE_GO), "✅ "),
			decor.Name(" ] "),
			decor.AverageSpeed(decor.SizeB1024(0), "% .2f", decor.WCSyncWidth),
		),
	)
	if info.Resumed > 0 {
		r.sum = info.Resumed
		r.total.SetCurrent(info.Resumed)
		r.total.SetRefill(info.Resumed)
	}
}

func (r *progressReporter) ChunkStart(id int, _, length, written int64) {
	r.mu.Lock()
	if _, ok := r.bars[id]; ok {
		r.mu.Unlock()
		return
	}
	if length < 0 {
		r.mu.Unlock()
		return // unknown size: no meaningful bar to draw
	}
	defer r.mu.Unlock()
	r.ensureProgress()
	bar := r.p.New(length,
		barStyle(),
		mpb.BarPriority(id),
		mpb.BarRemoveOnComplete(),
		mpb.PrependDecorators(
			decor.Name(fmt.Sprintf("    part %02d", id), decor.WCSyncWidthR),
			decor.NewPercentage(" % d", decor.WCSyncSpace),
		),
		mpb.AppendDecorators(
			decor.EwmaSpeed(decor.SizeB1024(0), "% .1f", 30, decor.WCSyncSpace),
		),
	)
	if written > 0 {
		bar.SetCurrent(written)
		bar.SetRefill(written)
	}
	r.counted[id] = written
	r.bars[id] = &chunkBar{bar: bar, length: length}
}

// ChunkResize shrinks a chunk whose tail was stolen or requeued. It does not
// change counted progress: the bytes remain assigned elsewhere in the run.
func (r *progressReporter) ChunkResize(id int, length int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	chunk, ok := r.bars[id]
	if !ok || chunk.done || chunk.bar == nil || length < 0 || length > chunk.length {
		return
	}
	chunk.bar.SetTotal(length, false)
	chunk.length = length
}

// ChunkRestart rolls a single-stream retry back to zero without double
// counting the discarded attempt in the aggregate bar.
func (r *progressReporter) ChunkRestart(id int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	chunk, ok := r.bars[id]
	if !ok || chunk.done || chunk.bar == nil {
		return
	}
	r.sum -= r.counted[id]
	if r.sum < 0 {
		r.sum = 0
	}
	r.counted[id] = 0
	chunk.bar.SetCurrent(0)
	if r.total != nil {
		r.total.SetCurrent(r.sum)
	}
}

func (r *progressReporter) Connected(id int, addr string) {
	log.Debugf("part %02d connected to %s", id, addr)
}

func (r *progressReporter) ChunkProgress(id int, n int, d time.Duration) {
	r.mu.Lock()
	chunk, ok := r.bars[id]
	if !ok || chunk.done {
		r.mu.Unlock()
		return
	}
	if n > 0 {
		r.counted[id] += int64(n)
		r.sum += int64(n)
		if r.total != nil {
			r.total.SetCurrent(r.sum)
		}
	}
	r.mu.Unlock()
	chunk.bar.EwmaIncrBy(n, d)
}

func (r *progressReporter) ChunkRetry(id int, attempt int, err error) {
	r.mu.Lock()
	p := r.p
	r.mu.Unlock()
	if p != nil {
		fmt.Fprintf(p, "part %02d retry #%d: %v\n", id, attempt, err)
		return
	}
	log.Warnf("part %02d retry #%d: %v", id, attempt, err)
}

func (r *progressReporter) ChunkDone(id int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	chunk, ok := r.bars[id]
	if !ok {
		chunk = &chunkBar{} // record completion even if no bar was drawn
		r.bars[id] = chunk
	}
	if chunk.bar != nil && !chunk.done {
		chunk.bar.SetTotal(-1, true) // complete at current progress
	}
	chunk.done = true
}

func (r *progressReporter) Done(err error) {
	r.mu.Lock()
	if r.p == nil {
		r.mu.Unlock()
		return
	}
	if err != nil {
		if r.total != nil {
			r.total.Abort(false)
		}
		for _, chunk := range r.bars {
			if chunk.bar != nil && !chunk.done {
				chunk.bar.Abort(true)
			}
		}
	} else if r.total != nil {
		r.total.SetTotal(-1, true)
	}
	p := r.p
	r.mu.Unlock()
	p.Wait()
}
