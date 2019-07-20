package mpb

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/vbauerster/mpb/v4/decor"
)

// Filler interface.
// Bar renders by calling Filler's Fill method. You can literally have
// any bar kind, by implementing this interface and passing it to the
// Add method.
type Filler interface {
	Fill(w io.Writer, width int, stat *decor.Statistics)
}

// FillerFunc is function type adapter to convert function into Filler.
type FillerFunc func(w io.Writer, width int, stat *decor.Statistics)

func (f FillerFunc) Fill(w io.Writer, width int, stat *decor.Statistics) {
	f(w, width, stat)
}

// Bar represents a progress Bar.
type Bar struct {
	priority int // used by heap
	index    int // used by heap

	extendedLines int
	toShutdown    bool
	toDrop        bool
	noPop         bool
	operateState  chan func(*bState)
	frameCh       chan io.Reader
	syncTableCh   chan [][]chan int
	completed     chan bool

	// concel is called either by user or on complete event
	cancel func()
	// done is closed after cacheState is assigned
	done chan struct{}
	// cacheState is populated, right after close(shutdown)
	cacheState *bState

	arbitraryCurrent struct {
		sync.Mutex
		current int64
	}

	container      *Progress
	dlogger        *log.Logger
	recoveredPanic interface{}
}

type bState struct {
	filler            Filler
	extender          Filler
	id                int
	width             int
	total             int64
	current           int64
	trimSpace         bool
	toComplete        bool
	completeFlushed   bool
	noBufBOnComplete  bool
	noPop             bool
	aDecorators       []decor.Decorator
	pDecorators       []decor.Decorator
	amountReceivers   []decor.AmountReceiver
	shutdownListeners []decor.ShutdownListener
	bufP, bufB, bufA  *bytes.Buffer
	bufE              *bytes.Buffer

	// priority overrides *Bar's priority, if set
	priority int
	// dropOnComplete propagates to *Bar
	dropOnComplete bool
	// runningBar is a key for *pState.parkedBars
	runningBar *Bar

	debugOut io.Writer
}

func newBar(container *Progress, bs *bState) *Bar {

	bs.bufP = bytes.NewBuffer(make([]byte, 0, bs.width))
	bs.bufB = bytes.NewBuffer(make([]byte, 0, bs.width))
	bs.bufA = bytes.NewBuffer(make([]byte, 0, bs.width))
	if bs.extender != nil {
		bs.bufE = bytes.NewBuffer(make([]byte, 0, bs.width))
	}

	logPrefix := fmt.Sprintf("%sbar#%02d ", container.dlogger.Prefix(), bs.id)
	ctx, cancel := context.WithCancel(container.ctx)
	bar := &Bar{
		container:    container,
		priority:     bs.priority,
		toDrop:       bs.dropOnComplete,
		noPop:        bs.noPop,
		operateState: make(chan func(*bState)),
		frameCh:      make(chan io.Reader, 1),
		syncTableCh:  make(chan [][]chan int),
		completed:    make(chan bool, 1),
		done:         make(chan struct{}),
		cancel:       cancel,
		dlogger:      log.New(bs.debugOut, logPrefix, log.Lshortfile),
	}

	go bar.serve(ctx, bs)
	return bar
}

// RemoveAllPrependers removes all prepend functions.
func (b *Bar) RemoveAllPrependers() {
	select {
	case b.operateState <- func(s *bState) { s.pDecorators = nil }:
	case <-b.done:
	}
}

// RemoveAllAppenders removes all append functions.
func (b *Bar) RemoveAllAppenders() {
	select {
	case b.operateState <- func(s *bState) { s.aDecorators = nil }:
	case <-b.done:
	}
}

// ProxyReader wraps r with metrics required for progress tracking.
func (b *Bar) ProxyReader(r io.Reader) io.ReadCloser {
	if r == nil {
		return nil
	}
	rc, ok := r.(io.ReadCloser)
	if !ok {
		rc = ioutil.NopCloser(r)
	}
	return &proxyReader{rc, b, time.Now()}
}

// ID returs id of the bar.
func (b *Bar) ID() int {
	result := make(chan int)
	select {
	case b.operateState <- func(s *bState) { result <- s.id }:
		return <-result
	case <-b.done:
		return b.cacheState.id
	}
}

// Current returns bar's current number, in other words sum of all increments.
func (b *Bar) Current() int64 {
	result := make(chan int64)
	select {
	case b.operateState <- func(s *bState) { result <- s.current }:
		return <-result
	case <-b.done:
		return b.cacheState.current
	}
}

// SetRefill sets refill, if supported by underlying Filler.
func (b *Bar) SetRefill(amount int64) {
	b.operateState <- func(s *bState) {
		if f, ok := s.filler.(interface{ SetRefill(int64) }); ok {
			f.SetRefill(amount)
		}
	}
}

// SetTotal sets total dynamically.
// Set complete to true, to trigger bar complete event now.
func (b *Bar) SetTotal(total int64, complete bool) {
	select {
	case b.operateState <- func(s *bState) {
		s.total = total
		if complete && !s.toComplete {
			s.current = s.total
			s.toComplete = true
			go b.refreshNowTillShutdown()
		}
	}:
	case <-b.done:
	}
}

// SetCurrent sets progress' current to arbitrary amount.
func (b *Bar) SetCurrent(current int64, wdd ...time.Duration) {
	if current <= 0 {
		return
	}
	b.arbitraryCurrent.Lock()
	last := b.arbitraryCurrent.current
	b.IncrBy(int(current-last), wdd...)
	b.arbitraryCurrent.current = current
	b.arbitraryCurrent.Unlock()
}

// Increment is a shorthand for b.IncrInt64(1, wdd...).
func (b *Bar) Increment(wdd ...time.Duration) {
	b.IncrInt64(1, wdd...)
}

// IncrBy is a shorthand for b.IncrInt64(int64(n), wdd...).
func (b *Bar) IncrBy(n int, wdd ...time.Duration) {
	b.IncrInt64(int64(n), wdd...)
}

// IncrInt64 increments progress bar by amount of n. wdd is an optional
// work duration i.e. time.Since(start), which expected to be passed,
// if any ewma based decorator is used.
func (b *Bar) IncrInt64(n int64, wdd ...time.Duration) {
	select {
	case b.operateState <- func(s *bState) {
		s.current += n
		if s.total > 0 && s.current >= s.total {
			s.current = s.total
			s.toComplete = true
			go b.refreshNowTillShutdown()
		}
		for _, ar := range s.amountReceivers {
			ar.NextAmount(n, wdd...)
		}
	}:
	case <-b.done:
	}
}

// SetPriority changes bar's order among multiple bars. Zero is highest
// priority, i.e. bar will be on top. If you don't need to set priority
// dynamically, better use BarPriority option.
func (b *Bar) SetPriority(priority int) {
	select {
	case <-b.done:
	default:
		b.container.setBarPriority(b, priority)
	}
}

// Abort interrupts bar's running goroutine. Call this, if you'd like
// to stop/remove bar before completion event. It has no effect after
// completion event. If drop is true bar will be removed as well.
func (b *Bar) Abort(drop bool) {
	select {
	case <-b.done:
	default:
		if drop {
			b.container.dropBar(b)
		}
		b.cancel()
	}
}

// Completed reports whether the bar is in completed state.
func (b *Bar) Completed() bool {
	select {
	case b.operateState <- func(s *bState) { b.completed <- s.toComplete }:
		return <-b.completed
	case <-b.done:
		return true
	}
}

func (b *Bar) wSyncTable() [][]chan int {
	select {
	case b.operateState <- func(s *bState) { b.syncTableCh <- s.wSyncTable() }:
		return <-b.syncTableCh
	case <-b.done:
		return b.cacheState.wSyncTable()
	}
}

func (b *Bar) serve(ctx context.Context, s *bState) {
	defer b.container.bwg.Done()
	for {
		select {
		case op := <-b.operateState:
			op(s)
		case <-ctx.Done():
			b.cacheState = s
			close(b.done)
			// Notifying decorators about shutdown event
			for _, sl := range s.shutdownListeners {
				sl.Shutdown()
			}
			return
		}
	}
}

func (b *Bar) render(tw int) {
	if b.recoveredPanic != nil {
		b.toShutdown = false
		b.frameCh <- b.panicToFrame(tw)
		return
	}
	select {
	case b.operateState <- func(s *bState) {
		defer func() {
			// recovering if user defined decorator panics for example
			if p := recover(); p != nil {
				b.dlogger.Println(p)
				b.recoveredPanic = p
				b.toShutdown = !s.completeFlushed
				b.frameCh <- b.panicToFrame(tw)
			}
		}()

		frame := s.draw(tw)

		if s.extender != nil {
			s.extender.Fill(s.bufE, tw, newStatistics(s))
			b.extendedLines = countLines(s.bufE.Bytes())
			frame = io.MultiReader(frame, s.bufE)
		}

		b.toShutdown = s.toComplete && !s.completeFlushed
		s.completeFlushed = s.toComplete

		b.frameCh <- frame
	}:
	case <-b.done:
		s := b.cacheState
		frame := s.draw(tw)
		if s.extender != nil {
			s.extender.Fill(s.bufE, tw, newStatistics(s))
			b.extendedLines = countLines(s.bufE.Bytes())
			frame = io.MultiReader(frame, s.bufE)
		}
		b.frameCh <- frame
	}
}

func (b *Bar) panicToFrame(termWidth int) io.Reader {
	return strings.NewReader(fmt.Sprintf(fmt.Sprintf("%%.%dv\n", termWidth), b.recoveredPanic))
}

func (s *bState) draw(termWidth int) io.Reader {

	stat := newStatistics(s)

	for _, d := range s.pDecorators {
		s.bufP.WriteString(d.Decor(stat))
	}

	for _, d := range s.aDecorators {
		s.bufA.WriteString(d.Decor(stat))
	}

	s.bufA.WriteByte('\n')
	if s.noBufBOnComplete && s.completeFlushed {
		return io.MultiReader(s.bufP, s.bufA)
	}

	prependCount := utf8.RuneCount(s.bufP.Bytes())
	appendCount := utf8.RuneCount(s.bufA.Bytes()) - 1

	if fitWidth := s.width; termWidth > 1 {
		if !s.trimSpace {
			// reserve space for edge spaces
			termWidth -= 2
			s.bufB.WriteByte(' ')
			defer s.bufB.WriteByte(' ')
		}
		if prependCount+s.width+appendCount > termWidth {
			fitWidth = termWidth - prependCount - appendCount
		}
		s.filler.Fill(s.bufB, fitWidth, stat)
	}

	return io.MultiReader(s.bufP, s.bufB, s.bufA)
}

func (s *bState) wSyncTable() [][]chan int {
	columns := make([]chan int, 0, len(s.pDecorators)+len(s.aDecorators))
	var pCount int
	for _, d := range s.pDecorators {
		if ch, ok := d.Sync(); ok {
			columns = append(columns, ch)
			pCount++
		}
	}
	var aCount int
	for _, d := range s.aDecorators {
		if ch, ok := d.Sync(); ok {
			columns = append(columns, ch)
			aCount++
		}
	}
	table := make([][]chan int, 2)
	table[0] = columns[0:pCount]
	table[1] = columns[pCount : pCount+aCount : pCount+aCount]
	return table
}

func (b *Bar) refreshNowTillShutdown() {
	for {
		select {
		case b.container.forceRefresh <- time.Now():
		case <-b.done:
			return
		}
	}
}

func newStatistics(s *bState) *decor.Statistics {
	return &decor.Statistics{
		ID:        s.id,
		Completed: s.completeFlushed,
		Total:     s.total,
		Current:   s.current,
	}
}

func countLines(b []byte) int {
	return bytes.Count(b, []byte("\n"))
}
