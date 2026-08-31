package download

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/apex/log"
	godl "github.com/blacktop/go-download"
	"github.com/vbauerster/cupwriter"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
	"golang.org/x/term"
)

const totalBarPriority = 1 << 20

const (
	// barMaxWidth is the historical fixed bar width.
	barMaxWidth = 60
	// barMinWidth keeps a bar legible on very narrow terminals.
	barMinWidth = 12
	// barDecorOverhead approximates the widest prepend/append decoration
	// around a bar (aggregate counters, ETA, speed). Rendered lines longer
	// than the terminal wrap, and wrapped lines break mpb's in-place redraw
	// by stranding duplicate frames in scrollback.
	barDecorOverhead = 50
)

// progressSinks routes log lines emitted while bars are on screen through the
// live mpb container: writing to the terminal behind the renderer's back
// scrolls the screen, so the next redraw lands below the old frame and leaves
// it stranded. Registrations form a stack because a Download is documented as
// one-per-concurrent-batch: when the newest download finishes and clears its
// container, lines keep flowing through the next one still rendering instead
// of leaking past the renderer.
var progressSinks struct {
	mu    sync.Mutex
	stack []io.Writer
}

// stderrIsTerminal reports whether stderr renders in place. Overridable for
// tests. Without a terminal mpb runs in no-render mode where container writes
// succeed but are never flushed, so the sink must stay unregistered and apex
// must keep every record.
var stderrIsTerminal = func() bool {
	return term.IsTerminal(int(os.Stderr.Fd()))
}

func setProgressSink(w io.Writer) {
	progressSinks.mu.Lock()
	defer progressSinks.mu.Unlock()
	progressSinks.stack = removeProgressSink(progressSinks.stack, w)
	progressSinks.stack = append(progressSinks.stack, w)
}

// clearProgressSink detaches w wherever it sits in the stack; an older sink
// below it (a download still rendering) becomes active again.
func clearProgressSink(w io.Writer) {
	progressSinks.mu.Lock()
	defer progressSinks.mu.Unlock()
	progressSinks.stack = removeProgressSink(progressSinks.stack, w)
}

func removeProgressSink(stack []io.Writer, w io.Writer) []io.Writer {
	out := stack[:0]
	for _, entry := range stack {
		if entry != w {
			out = append(out, entry)
		}
	}
	// Release removed writers from the global slice's backing array.
	clear(stack[len(out):])
	return out
}

func activeProgressWriter() io.Writer {
	progressSinks.mu.Lock()
	defer progressSinks.mu.Unlock()
	if len(progressSinks.stack) == 0 {
		return nil
	}
	return progressSinks.stack[len(progressSinks.stack)-1]
}

// writeThroughProgressSink delivers one already-terminated line through the
// live container stack. A write failure means that container shut down
// between the lookup and the write, so the line retries against the next
// live sink, excluding writers that already failed; it reports false only
// when no rendering container remains and apex should take the line.
func writeThroughProgressSink(line string) bool {
	var failed []io.Writer
	for {
		w := activeProgressWriterExcluding(failed)
		if w == nil {
			return false
		}
		if _, err := io.WriteString(w, line); err == nil {
			return true
		}
		failed = append(failed, w)
	}
}

func activeProgressWriterExcluding(failed []io.Writer) io.Writer {
	progressSinks.mu.Lock()
	defer progressSinks.mu.Unlock()
next:
	for _, w := range slices.Backward(progressSinks.stack) {
		for _, f := range failed {
			if f == w {
				continue next
			}
		}
		return w
	}
	return nil
}

// reporterSink is the lifecycle-aware writer a reporter registers instead of
// its raw container. mpb acknowledges a write and flushes it only on a later
// refresh cycle, so the console keeps a recovery copy until a flush confirms
// delivery. Once teardown begins the sink buffers new lines instead of
// forwarding them, and Done replays every unconfirmed line after the last
// frame has rendered.
type reporterSink struct {
	mu       sync.Mutex
	p        *mpb.Progress
	console  *progressConsoleWriter
	held     bytes.Buffer
	draining bool
	closed   bool
}

func (s *reporterSink) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, io.ErrClosedPipe
	}
	if s.draining {
		return s.held.Write(b)
	}
	return s.p.Write(b)
}

// beginDrain stops forwarding to the container before its final renders; the
// mutex also waits out any in-flight forwarded write.
func (s *reporterSink) beginDrain() {
	s.mu.Lock()
	s.draining = true
	s.mu.Unlock()
}

// closeAndTake makes stale writes fail so the dispatcher retries a live sink.
// It includes writes that entered before close acquired the mutex, preventing
// an acknowledged append after the one-shot replay.
func (s *reporterSink) closeAndTake() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	held := s.held.String()
	s.held.Reset()
	if s.console == nil {
		return held
	}
	return s.console.takePending() + held
}

// progressConsoleWriter keeps a recovery copy of intercepted log writes until
// a successful terminal flush, without changing cupwriter's cursor handling
// or terminal-size detection. Bar frames arrive through ReadFrom and therefore
// are deliberately not retained for replay. mpb serializes these methods, and
// takePending runs only after Progress.Wait returns.
type progressConsoleWriter struct {
	mpb.ConsoleWriter
	pending bytes.Buffer
}

func (w *progressConsoleWriter) Write(b []byte) (int, error) {
	n, err := w.ConsoleWriter.Write(b)
	if n > 0 {
		w.pending.Write(b[:n])
	}
	return n, err
}

func (w *progressConsoleWriter) Flush(lines int) error {
	if err := w.ConsoleWriter.Flush(lines); err != nil {
		return err
	}
	w.pending.Reset()
	return nil
}

func (w *progressConsoleWriter) takePending() string {
	pending := w.pending.String()
	w.pending.Reset()
	return pending
}

// replayProgressLines delivers lines held during teardown to the next live
// container, or straight to stderr, which is stable again once the final frame
// is done and no renderer owns the cursor.
func replayProgressLines(held string) {
	if held == "" {
		return
	}
	if !writeThroughProgressSink(held) {
		_, _ = io.WriteString(os.Stderr, held)
	}
}

// progressBarWidth clamps the bar so the widest decorated line fits cols.
func progressBarWidth(cols int) int {
	width := cols - barDecorOverhead
	if width >= barMaxWidth {
		return barMaxWidth
	}
	if width < barMinWidth {
		return barMinWidth
	}
	return width
}

// terminalBarWidth sizes bars for the render target (stderr); without a
// terminal the historical fixed width stands.
func terminalBarWidth() int {
	cols, _, err := term.GetSize(int(os.Stderr.Fd()))
	if err != nil || cols <= 0 {
		return barMaxWidth
	}
	return progressBarWidth(cols)
}

const (
	// rateWindow bounds the smoothing window for the aggregate speed.
	rateWindow = 5 * time.Second
	// rateSampleEvery throttles sample retention under concurrent parts.
	rateSampleEvery = 100 * time.Millisecond
	// rateMinSpan is the shortest window that yields a meaningful rate.
	rateMinSpan = 250 * time.Millisecond
)

type rateSample struct {
	at    time.Time
	bytes int64
}

// aggregateRate measures session bandwidth from fresh durable bytes over wall
// clock. Resumed bytes seed the visual bars but never this tracker, so a
// resumed download cannot inflate the reported rate or shrink the ETA.
type aggregateRate struct {
	mu      sync.Mutex
	now     func() time.Time
	bytes   int64
	samples []rateSample
}

func (a *aggregateRate) add(n int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.bytes += n
	now := a.now()
	// snapshots keep their timestamps: appending only after the interval
	// elapses is what rolls the baseline forward under high-frequency events
	if count := len(a.samples); count == 0 || now.Sub(a.samples[count-1].at) >= rateSampleEvery {
		a.samples = append(a.samples, rateSample{at: now, bytes: a.bytes})
	}
	a.prune(now)
}

// prune drops samples that no longer bound the window, always retaining one
// sample older than the window as the rate baseline. Must be called with a.mu
// held.
func (a *aggregateRate) prune(now time.Time) {
	for len(a.samples) >= 2 && now.Sub(a.samples[1].at) >= rateWindow {
		a.samples = a.samples[1:]
	}
}

// reset clears the sampling baseline after durable progress was rolled back,
// so discarded bytes cannot inflate the next window's rate.
func (a *aggregateRate) reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.samples = a.samples[:0]
}

// perSecond returns the smoothed fresh-bytes rate, or 0 before the window
// holds a meaningful span. A stalled transfer decays toward 0.
func (a *aggregateRate) perSecond() float64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.samples) == 0 {
		return 0
	}
	now := a.now()
	a.prune(now)
	base := a.samples[0]
	span := now.Sub(base.at)
	if span < rateMinSpan {
		return 0
	}
	return float64(a.bytes-base.bytes) / span.Seconds()
}

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
	sink    *reporterSink
	bars    map[int]*chunkBar
	counted map[int]int64
	sum     int64
	total   *mpb.Bar
	rate    aggregateRate
}

func newProgressReporter() *progressReporter {
	return &progressReporter{
		bars:    make(map[int]*chunkBar),
		counted: make(map[int]int64),
		rate:    aggregateRate{now: time.Now},
	}
}

var (
	_ godl.Reporter       = (*progressReporter)(nil)
	_ godl.ChunkResizer   = (*progressReporter)(nil)
	_ godl.ChunkRestarter = (*progressReporter)(nil)
)

// ensureProgress lazily starts the mpb renderer. Must be called with r.mu
// held. Single-stream downloads can recover a size the probe could not, so
// ChunkStart needs this as well as Start. Bars render to stderr — the same
// stream apex logs use — and while they are live the process-wide sink
// interleaves log lines through the container instead of around it.
func (r *progressReporter) ensureProgress() {
	if r.p != nil {
		return
	}
	if stderrIsTerminal() {
		console := &progressConsoleWriter{
			ConsoleWriter: cupwriter.New(os.Stderr, false),
		}
		r.p = mpb.New(
			mpb.WithWidth(terminalBarWidth()),
			mpb.WithConsoleWriter(console),
			mpb.WithRefreshRate(180*time.Millisecond),
		)
		r.sink = &reporterSink{p: r.p, console: console}
		setProgressSink(r.sink)
		return
	}
	r.p = mpb.New(
		mpb.WithWidth(terminalBarWidth()),
		mpb.WithOutput(os.Stderr),
		mpb.WithRefreshRate(180*time.Millisecond),
	)
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
			decor.OnComplete(decor.Any(r.aggregateETA), "✅ "),
			decor.Name(" ] "),
			decor.Any(r.aggregateSpeed, decor.WCSyncWidth),
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
	r.rate.reset()
	chunk.bar.SetCurrent(0)
	if r.total != nil {
		r.total.SetCurrent(r.sum)
	}
}

// aggregateSpeed renders the fresh-bytes windowed rate. Resumed bytes count
// toward the bar position but never toward this rate.
func (r *progressReporter) aggregateSpeed(_ decor.Statistics) string {
	return fmt.Sprintf("% .2f", decor.FmtAsSpeed(decor.SizeB1024(math.Round(r.rate.perSecond()))))
}

// aggregateETA divides remaining bytes by the fresh aggregate rate; without a
// meaningful rate, or when the result cannot fit in time.Duration, it reports
// an honest unavailable state.
func (r *progressReporter) aggregateETA(s decor.Statistics) string {
	rate := r.rate.perSecond()
	if rate <= 0 {
		return "--"
	}
	seconds := float64(max(s.Total-s.Current, 0)) / rate
	if seconds >= float64(math.MaxInt64/time.Second) {
		return "--" // beyond time.Duration: no representable ETA
	}
	return time.Duration(seconds * float64(time.Second)).Truncate(time.Second).String()
}

// Connected reports engine connections through the live container so the
// in-place redraw survives, via apex otherwise. Like the log.Debugf it
// replaces, it only speaks under --verbose.
func (r *progressReporter) Connected(id int, addr string) {
	if !apexDebugEnabled() {
		return
	}
	if writeThroughProgressSink(fmt.Sprintf("part %02d connected to %s\n", id, addr)) {
		return
	}
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
		r.rate.add(int64(n))
		if r.total != nil {
			r.total.SetCurrent(r.sum)
		}
	}
	r.mu.Unlock()
	chunk.bar.EwmaIncrBy(n, d)
}

// ChunkRetry warns through the live container when one is rendering; apex
// keeps the warning otherwise — writing to a no-render container would
// acknowledge the bytes without ever flushing them.
func (r *progressReporter) ChunkRetry(id int, attempt int, err error) {
	if writeThroughProgressSink(fmt.Sprintf("part %02d retry #%d: %v\n", id, attempt, err)) {
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
	sink := r.sink
	if sink != nil {
		// Drain before the final renders: a container write acknowledged
		// after the last refresh would be discarded during Wait.
		sink.beginDrain()
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
	if sink != nil {
		// Ownership held through the final redraw: lines emitted during
		// teardown were buffered, not raced against the last frames. Now
		// the container is gone, hand the sink back and deliver them.
		held := sink.closeAndTake()
		clearProgressSink(sink)
		replayProgressLines(held)
	}
}
