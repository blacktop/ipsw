package mpb

import (
	"container/heap"
	"context"
	"io"
	"io/ioutil"
	"log"
	"os"
	"sync"
	"time"

	"github.com/vbauerster/mpb/v4/cwriter"
)

const (
	// default RefreshRate
	prr = 120 * time.Millisecond
	// default width
	pwidth = 80
)

// Progress represents the container that renders Progress bars
type Progress struct {
	ctx          context.Context
	uwg          *sync.WaitGroup
	cwg          *sync.WaitGroup
	bwg          *sync.WaitGroup
	operateState chan func(*pState)
	done         chan struct{}
	forceRefresh chan time.Time
	once         sync.Once
	dlogger      *log.Logger
}

type pState struct {
	bHeap            priorityQueue
	heapUpdated      bool
	pMatrix          map[int][]chan int
	aMatrix          map[int][]chan int
	barShutdownQueue []*Bar
	barPopQueue      []*Bar

	// following are provided/overrided by user
	idCount          int
	width            int
	popCompleted     bool
	rr               time.Duration
	uwg              *sync.WaitGroup
	manualRefreshCh  <-chan time.Time
	shutdownNotifier chan struct{}
	parkedBars       map[*Bar]*Bar
	output           io.Writer
	debugOut         io.Writer
}

// New creates new Progress container instance. It's not possible to
// reuse instance after *Progress.Wait() method has been called.
func New(options ...ContainerOption) *Progress {
	return NewWithContext(context.Background(), options...)
}

// NewWithContext creates new Progress container instance with provided
// context. It's not possible to reuse instance after *Progress.Wait()
// method has been called.
func NewWithContext(ctx context.Context, options ...ContainerOption) *Progress {

	s := &pState{
		bHeap:      priorityQueue{},
		width:      pwidth,
		rr:         prr,
		parkedBars: make(map[*Bar]*Bar),
		output:     os.Stdout,
		debugOut:   ioutil.Discard,
	}

	for _, opt := range options {
		if opt != nil {
			opt(s)
		}
	}

	p := &Progress{
		ctx:          ctx,
		uwg:          s.uwg,
		cwg:          new(sync.WaitGroup),
		bwg:          new(sync.WaitGroup),
		operateState: make(chan func(*pState)),
		forceRefresh: make(chan time.Time),
		done:         make(chan struct{}),
		dlogger:      log.New(s.debugOut, "[mpb] ", log.Lshortfile),
	}
	p.cwg.Add(1)
	go p.serve(s, cwriter.New(s.output))
	return p
}

// AddBar creates a new progress bar and adds to the container.
func (p *Progress) AddBar(total int64, options ...BarOption) *Bar {
	return p.Add(total, newDefaultBarFiller(), options...)
}

// AddSpinner creates a new spinner bar and adds to the container.
func (p *Progress) AddSpinner(total int64, alignment SpinnerAlignment, options ...BarOption) *Bar {
	filler := &spinnerFiller{
		frames:    defaultSpinnerStyle,
		alignment: alignment,
	}
	return p.Add(total, filler, options...)
}

// Add creates a bar which renders itself by provided filler.
// Set total to 0, if you plan to update it later.
func (p *Progress) Add(total int64, filler Filler, options ...BarOption) *Bar {
	if filler == nil {
		filler = newDefaultBarFiller()
	}
	p.bwg.Add(1)
	result := make(chan *Bar)
	select {
	case p.operateState <- func(ps *pState) {
		bs := &bState{
			total:    total,
			filler:   filler,
			priority: ps.idCount,
			id:       ps.idCount,
			width:    ps.width,
			debugOut: ps.debugOut,
		}
		for _, opt := range options {
			if opt != nil {
				opt(bs)
			}
		}
		bar := newBar(p, bs)
		if bs.runningBar != nil {
			bs.runningBar.noPop = true
			ps.parkedBars[bs.runningBar] = bar
		} else {
			heap.Push(&ps.bHeap, bar)
			ps.heapUpdated = true
		}
		ps.idCount++
		result <- bar
	}:
		return <-result
	case <-p.done:
		p.bwg.Done()
		return nil
	}
}

func (p *Progress) dropBar(b *Bar) {
	select {
	case p.operateState <- func(s *pState) {
		if b.index < 0 {
			return
		}
		heap.Remove(&s.bHeap, b.index)
		s.heapUpdated = true
	}:
	case <-p.done:
	}
}

func (p *Progress) setBarPriority(b *Bar, priority int) {
	select {
	case p.operateState <- func(s *pState) {
		if b.index < 0 {
			return
		}
		b.priority = priority
		heap.Fix(&s.bHeap, b.index)
	}:
	case <-p.done:
	}
}

// UpdateBarPriority same as *Bar.SetPriority.
func (p *Progress) UpdateBarPriority(b *Bar, priority int) {
	p.setBarPriority(b, priority)
}

// BarCount returns bars count
func (p *Progress) BarCount() int {
	result := make(chan int, 1)
	select {
	case p.operateState <- func(s *pState) { result <- s.bHeap.Len() }:
		return <-result
	case <-p.done:
		return 0
	}
}

// Wait waits far all bars to complete and finally shutdowns container.
// After this method has been called, there is no way to reuse *Progress
// instance.
func (p *Progress) Wait() {
	if p.uwg != nil {
		// wait for user wg
		p.uwg.Wait()
	}

	// wait for bars to quit, if any
	p.bwg.Wait()

	p.once.Do(p.shutdown)

	// wait for container to quit
	p.cwg.Wait()
}

func (p *Progress) shutdown() {
	close(p.done)
}

func (p *Progress) serve(s *pState, cw *cwriter.Writer) {
	defer p.cwg.Done()

	manualOrTickCh, cleanUp := s.manualOrTick()
	defer cleanUp()

	refreshCh := fanInRefreshSrc(p.done, p.forceRefresh, manualOrTickCh)

	for {
		select {
		case op := <-p.operateState:
			op(s)
		case _, ok := <-refreshCh:
			if !ok {
				if s.shutdownNotifier != nil {
					close(s.shutdownNotifier)
				}
				return
			}
			if err := s.render(cw); err != nil {
				p.dlogger.Println(err)
			}
		}
	}
}

func (s *pState) render(cw *cwriter.Writer) error {
	if s.heapUpdated {
		s.updateSyncMatrix()
		s.heapUpdated = false
	}
	syncWidth(s.pMatrix)
	syncWidth(s.aMatrix)

	tw, err := cw.GetWidth()
	if err != nil {
		tw = s.width
	}
	for i := 0; i < s.bHeap.Len(); i++ {
		bar := s.bHeap[i]
		go bar.render(tw)
	}

	return s.flush(cw)
}

func (s *pState) flush(cw *cwriter.Writer) error {
	var lineCount int
	bm := make(map[*Bar]struct{}, s.bHeap.Len())
	for s.bHeap.Len() > 0 {
		b := heap.Pop(&s.bHeap).(*Bar)
		cw.ReadFrom(<-b.frameCh)
		if b.toShutdown {
			// shutdown at next flush
			// this ensures no bar ends up with less than 100% rendered
			defer func() {
				s.barShutdownQueue = append(s.barShutdownQueue, b)
				if !b.noPop && s.popCompleted {
					b.priority = -1
				}
			}()
		}
		lineCount += b.extendedLines + 1
		bm[b] = struct{}{}
	}

	for _, b := range s.barShutdownQueue {
		if parkedBar := s.parkedBars[b]; parkedBar != nil {
			parkedBar.priority = b.priority
			heap.Push(&s.bHeap, parkedBar)
			delete(s.parkedBars, b)
			b.toDrop = true
		}
		if b.toDrop {
			delete(bm, b)
			s.heapUpdated = true
		} else if s.popCompleted {
			if b := b; !b.noPop {
				defer func() {
					s.barPopQueue = append(s.barPopQueue, b)
				}()
			}
		}
		b.cancel()
	}
	s.barShutdownQueue = s.barShutdownQueue[0:0]

	for _, b := range s.barPopQueue {
		delete(bm, b)
		s.heapUpdated = true
		lineCount -= b.extendedLines + 1
	}
	s.barPopQueue = s.barPopQueue[0:0]

	for b := range bm {
		heap.Push(&s.bHeap, b)
	}

	return cw.Flush(lineCount)
}

func (s *pState) manualOrTick() (<-chan time.Time, func()) {
	if s.manualRefreshCh != nil {
		return s.manualRefreshCh, func() {}
	}
	ticker := time.NewTicker(s.rr)
	return ticker.C, ticker.Stop
}

func (s *pState) updateSyncMatrix() {
	s.pMatrix = make(map[int][]chan int)
	s.aMatrix = make(map[int][]chan int)
	for i := 0; i < s.bHeap.Len(); i++ {
		bar := s.bHeap[i]
		table := bar.wSyncTable()
		pRow, aRow := table[0], table[1]

		for i, ch := range pRow {
			s.pMatrix[i] = append(s.pMatrix[i], ch)
		}

		for i, ch := range aRow {
			s.aMatrix[i] = append(s.aMatrix[i], ch)
		}
	}
}

func syncWidth(matrix map[int][]chan int) {
	for _, column := range matrix {
		column := column
		go func() {
			var maxWidth int
			for _, ch := range column {
				if w := <-ch; w > maxWidth {
					maxWidth = w
				}
			}
			for _, ch := range column {
				ch <- maxWidth
			}
		}()
	}
}

func fanInRefreshSrc(done <-chan struct{}, channels ...<-chan time.Time) <-chan time.Time {
	var wg sync.WaitGroup
	multiplexedStream := make(chan time.Time)

	multiplex := func(c <-chan time.Time) {
		defer wg.Done()
		// source channels are never closed (time.Ticker never closes associated
		// channel), so we cannot simply range over a c, instead we use select
		// inside infinite loop
		for {
			select {
			case v := <-c:
				select {
				case multiplexedStream <- v:
				case <-done:
					return
				}
			case <-done:
				return
			}
		}
	}

	wg.Add(len(channels))
	for _, c := range channels {
		go multiplex(c)
	}

	go func() {
		wg.Wait()
		close(multiplexedStream)
	}()

	return multiplexedStream
}
