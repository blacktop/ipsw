package download

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/apex/log"
	"github.com/apex/log/handlers/memory"
	godl "github.com/blacktop/go-download"
	"github.com/vbauerster/mpb/v8"
)

func TestProgressBarWidthClampsToTerminal(t *testing.T) {
	tests := []struct {
		name string
		cols int
		want int
	}{
		{name: "wide terminal keeps historical width", cols: 200, want: barMaxWidth},
		{name: "exact fit keeps historical width", cols: barMaxWidth + barDecorOverhead, want: barMaxWidth},
		{name: "narrow terminal shrinks the bar", cols: 100, want: 100 - barDecorOverhead},
		{name: "tiny terminal floors at the minimum", cols: 30, want: barMinWidth},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := progressBarWidth(tt.cols); got != tt.want {
				t.Fatalf("progressBarWidth(%d) = %d, want %d", tt.cols, got, tt.want)
			}
		})
	}
}

func TestProgressSinkStackRestoresOlderDownload(t *testing.T) {
	var older, newer, foreign bytes.Buffer
	setProgressSink(&older)
	defer clearProgressSink(&older)
	setProgressSink(&newer)
	defer clearProgressSink(&newer)

	clearProgressSink(&foreign)
	if activeProgressWriter() != &newer {
		t.Fatal("a foreign clear detached the active sink")
	}
	// The newest download finishes first: the older one, still rendering,
	// must become the route again instead of leaving no sink at all.
	clearProgressSink(&newer)
	if activeProgressWriter() != &older {
		t.Fatal("clearing the newest sink must restore the older live download")
	}
	clearProgressSink(&older)
	if activeProgressWriter() != nil {
		t.Fatal("the last owner's clear must leave no sink")
	}
}

func TestRemoveProgressSinkClearsDiscardedTail(t *testing.T) {
	var kept, removed bytes.Buffer
	backing := []io.Writer{&removed, &kept, &removed}

	stack := removeProgressSink(backing, &removed)
	if len(stack) != 1 || stack[0] != &kept {
		t.Fatalf("compacted stack = %v, want only the retained writer", stack)
	}
	for i := len(stack); i < len(backing); i++ {
		if backing[i] != nil {
			t.Fatalf("discarded backing slot %d still retains %T", i, backing[i])
		}
	}
}

func TestEnsureProgressRegistersSinkOnlyOnTerminal(t *testing.T) {
	previous := stderrIsTerminal
	defer func() { stderrIsTerminal = previous }()

	stderrIsTerminal = func() bool { return false }
	nonTTY := newProgressReporter()
	nonTTY.mu.Lock()
	nonTTY.ensureProgress()
	nonTTY.mu.Unlock()
	if activeProgressWriter() != nil {
		nonTTY.Done(nil)
		t.Fatal("non-terminal stderr must not register a sink: container writes would be acknowledged but never flushed")
	}
	nonTTY.Done(nil)

	stderrIsTerminal = func() bool { return true }
	tty := newProgressReporter()
	tty.mu.Lock()
	tty.ensureProgress()
	sink := tty.sink
	tty.mu.Unlock()
	if sink == nil || activeProgressWriter() != sink {
		tty.Done(nil)
		t.Fatal("terminal stderr must register the reporter's lifecycle sink")
	}
	tty.Done(nil)
	if activeProgressWriter() != nil {
		t.Fatal("Done must clear the sink it registered")
	}
}

func TestEngineLogRoutesThroughActiveProgressSink(t *testing.T) {
	previous := log.Log.(*log.Logger).Handler
	defer log.SetHandler(previous)
	captured := memory.New()
	log.SetHandler(captured)

	var sink bytes.Buffer
	setProgressSink(&sink)
	defer clearProgressSink(&sink)

	engineLog.Warn("election lost", "b", 2, "a", 1)
	if len(captured.Entries) != 0 {
		t.Fatalf("apex received %d entries while the sink was active, want 0", len(captured.Entries))
	}
	if line := sink.String(); !strings.Contains(line, "⚠ godl: election lost a=1 b=2") {
		t.Fatalf("sink line = %q, want warn symbol, message, and fields in sorted order", line)
	}

	clearProgressSink(&sink)
	engineLog.Warn("election lost")
	if len(captured.Entries) != 1 || captured.Entries[0].Message != "godl: election lost" {
		t.Fatalf("apex must take over once the sink clears, got %+v", captured.Entries)
	}
	if strings.Count(sink.String(), "election lost") != 1 {
		t.Fatalf("a cleared sink still received lines: %q", sink.String())
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestEngineLogFallsBackToApexWhenSinkErrors(t *testing.T) {
	previous := log.Log.(*log.Logger).Handler
	defer log.SetHandler(previous)
	captured := memory.New()
	log.SetHandler(captured)

	setProgressSink(failingWriter{})
	defer clearProgressSink(failingWriter{})

	engineLog.Warn("stalled")
	if len(captured.Entries) != 1 || captured.Entries[0].Message != "godl: stalled" {
		t.Fatalf("a failing sink must fall back to apex, got %+v", captured.Entries)
	}
}

func TestSinkWriteFailureRetriesOlderLiveContainer(t *testing.T) {
	previous := log.Log.(*log.Logger).Handler
	defer log.SetHandler(previous)
	captured := memory.New()
	log.SetHandler(captured)

	var older bytes.Buffer
	setProgressSink(&older)
	defer clearProgressSink(&older)
	setProgressSink(failingWriter{}) // the newest container is shutting down
	defer clearProgressSink(failingWriter{})

	engineLog.Warn("stall")
	newProgressReporter().ChunkRetry(1, 2, errors.New("boom"))
	if len(captured.Entries) != 0 {
		t.Fatalf("apex received %d entries while an older container was live, want 0: %+v", len(captured.Entries), captured.Entries)
	}
	out := older.String()
	if !strings.Contains(out, "godl: stall") || !strings.Contains(out, "part 01 retry #2: boom") {
		t.Fatalf("older live container missed retried lines: %q", out)
	}
}

func TestClosedReporterSinkRejectsStaleWritesAndRetriesOlder(t *testing.T) {
	var older bytes.Buffer
	setProgressSink(&older)
	defer clearProgressSink(&older)

	sink := &reporterSink{draining: true}
	setProgressSink(sink)
	defer clearProgressSink(sink)
	fetched := activeProgressWriter()
	held := sink.closeAndTake()
	if held != "" {
		t.Fatalf("new sink held unexpected data %q", held)
	}
	if _, err := io.WriteString(fetched, "stale\n"); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("stale write error = %v, want %v", err, io.ErrClosedPipe)
	}
	if !writeThroughProgressSink("retried\n") {
		t.Fatal("dispatcher did not retry the older live sink")
	}
	if got := older.String(); got != "retried\n" {
		t.Fatalf("older sink output = %q, want retried line exactly once", got)
	}
}

type recordingConsoleWriter struct {
	pending bytes.Buffer
	output  bytes.Buffer
	flushed chan struct{}
}

func (w *recordingConsoleWriter) Write(b []byte) (int, error) { return w.pending.Write(b) }
func (w *recordingConsoleWriter) ReadFrom(r io.Reader) (int64, error) {
	return w.pending.ReadFrom(r)
}
func (*recordingConsoleWriter) IsTerminal() bool               { return true }
func (*recordingConsoleWriter) GetTermSize() (int, int, error) { return 120, 40, nil }
func (w *recordingConsoleWriter) Flush(int) error {
	_, err := w.pending.WriteTo(&w.output)
	w.flushed <- struct{}{}
	return err
}

func waitForConsoleFlush(t *testing.T, w *recordingConsoleWriter) {
	t.Helper()
	select {
	case <-w.flushed:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for progress refresh")
	}
}

func TestReporterSinkReplaysAcknowledgedLineWithoutFinalRefresh(t *testing.T) {
	refresh := make(chan any)
	console := &recordingConsoleWriter{flushed: make(chan struct{}, 16)}
	tracked := &progressConsoleWriter{ConsoleWriter: console}
	p := mpb.New(
		mpb.WithConsoleWriter(tracked),
		mpb.WithManualRefresh(refresh),
	)
	// Reproduce the idle-teardown window: render and remove the last bar,
	// then perform the empty cleanup refresh that clears hasUnrendered.
	completed := p.New(1, mpb.NopStyle(), mpb.BarRemoveOnComplete())
	completed.SetTotal(-1, true)
	waitForConsoleFlush(t, console)
	completed.Wait()
	refresh <- time.Now()
	waitForConsoleFlush(t, console)
	console.output.Reset()

	sink := &reporterSink{p: p, console: tracked}
	var older bytes.Buffer
	setProgressSink(&older)
	defer clearProgressSink(&older)
	setProgressSink(sink)
	defer clearProgressSink(sink)
	r := newProgressReporter()
	r.p = p
	r.sink = sink

	const line = "forwarded-before-drain\n"
	if !writeThroughProgressSink(line) {
		t.Fatal("live reporter sink rejected the pre-drain line")
	}
	r.Done(nil)
	if got := console.output.String(); got != "" {
		t.Fatalf("container rendered unexpectedly before shutdown: %q", got)
	}
	if got := older.String(); got != line {
		t.Fatalf("replayed output = %q, want acknowledged line exactly once", got)
	}
}

func TestReporterSinkDoesNotReplayConfirmedLine(t *testing.T) {
	refresh := make(chan any)
	console := &recordingConsoleWriter{flushed: make(chan struct{}, 16)}
	tracked := &progressConsoleWriter{ConsoleWriter: console}
	p := mpb.New(
		mpb.WithConsoleWriter(tracked),
		mpb.WithManualRefresh(refresh),
	)
	sink := &reporterSink{p: p, console: tracked}
	var older bytes.Buffer
	setProgressSink(&older)
	defer clearProgressSink(&older)
	setProgressSink(sink)
	defer clearProgressSink(sink)
	r := newProgressReporter()
	r.p = p
	r.sink = sink

	const line = "flushed-before-drain\n"
	if !writeThroughProgressSink(line) {
		t.Fatal("live reporter sink rejected the pre-drain line")
	}
	refresh <- time.Now()
	waitForConsoleFlush(t, console)
	r.Done(nil)
	if got := console.output.String(); got != line {
		t.Fatalf("container output = %q, want confirmed line exactly once", got)
	}
	if got := older.String(); got != "" {
		t.Fatalf("confirmed line was replayed after shutdown: %q", got)
	}
}

func TestDoneHandsSinkBackToOlderReporter(t *testing.T) {
	previous := stderrIsTerminal
	defer func() { stderrIsTerminal = previous }()
	stderrIsTerminal = func() bool { return true }

	older := newProgressReporter()
	older.mu.Lock()
	older.ensureProgress()
	olderSink := older.sink
	older.mu.Unlock()
	newer := newProgressReporter()
	newer.mu.Lock()
	newer.ensureProgress()
	newer.mu.Unlock()

	newer.Done(nil)
	if activeProgressWriter() != olderSink {
		older.Done(nil)
		t.Fatal("the newer download's Done must hand the sink back to the older live container")
	}
	older.Done(nil)
	if activeProgressWriter() != nil {
		t.Fatal("the last Done must leave no sink")
	}
}

// TestDoneHoldsSinkAndReplaysLinesBufferedDuringFinalization observes the
// finalization window itself: an incomplete chunk bar keeps Done blocked in
// p.Wait, and the assertions run while it is blocked. It fails against the
// clear-before-Wait ordering and against any sink that forwards teardown
// lines into the dying container instead of buffering them.
func TestDoneHoldsSinkAndReplaysLinesBufferedDuringFinalization(t *testing.T) {
	previousTerm := stderrIsTerminal
	defer func() { stderrIsTerminal = previousTerm }()
	stderrIsTerminal = func() bool { return true }
	previousHandler := log.Log.(*log.Logger).Handler
	defer log.SetHandler(previousHandler)
	captured := memory.New()
	log.SetHandler(captured)

	var olderDownload bytes.Buffer
	setProgressSink(&olderDownload)
	defer clearProgressSink(&olderDownload)

	r := newProgressReporter()
	r.Start(godl.Info{Total: 100})
	r.ChunkStart(0, 0, 100, 0) // incomplete chunk bar keeps Wait blocked
	sink := r.sink
	if sink == nil || activeProgressWriter() != sink {
		r.ChunkDone(0)
		r.Done(nil)
		t.Fatal("reporter must register its lifecycle sink")
	}

	doneReturned := make(chan struct{})
	go func() { r.Done(nil); close(doneReturned) }()
	defer func() {
		r.ChunkDone(0)
		select {
		case <-doneReturned:
		case <-time.After(time.Second):
			t.Error("Done did not return during test cleanup")
		}
	}()
	waitForSinkDrain(t, sink)
	select {
	case <-doneReturned:
		t.Fatal("Done returned with an incomplete chunk bar; the finalization window was not exercised")
	default:
	}

	if activeProgressWriter() != sink {
		r.ChunkDone(0)
		<-doneReturned
		t.Fatal("Done released the sink before the final redraw finished")
	}
	if !writeThroughProgressSink("during-finalization\n") {
		t.Fatal("a line during finalization must be accepted by the draining sink")
	}
	if strings.Contains(olderDownload.String(), "during-finalization") {
		t.Fatal("line leaked to the older download's renderer before the final frame")
	}

	r.ChunkDone(0)
	<-doneReturned
	if activeProgressWriter() != &olderDownload {
		t.Fatal("Done must hand the sink back to the older live download")
	}
	if !strings.Contains(olderDownload.String(), "during-finalization") {
		t.Fatal("the buffered line was lost instead of replayed after the final frame")
	}
	if len(captured.Entries) != 0 {
		t.Fatalf("apex received %d entries, want 0: %+v", len(captured.Entries), captured.Entries)
	}
}

func waitForSinkDrain(t *testing.T, sink *reporterSink) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for {
		sink.mu.Lock()
		draining := sink.draining
		sink.mu.Unlock()
		if draining {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("timed out waiting for reporter sink to begin draining")
		}
	}
}

func TestChunkRetryAndConnectedFollowTheSink(t *testing.T) {
	previousHandler := log.Log.(*log.Logger).Handler
	previousLevel := log.Log.(*log.Logger).Level
	defer func() {
		log.SetHandler(previousHandler)
		log.SetLevel(previousLevel)
	}()
	captured := memory.New()
	log.SetHandler(captured)
	log.SetLevel(log.DebugLevel)

	r := newProgressReporter()

	// No sink (non-TTY or bars not yet started): apex keeps both records.
	r.ChunkRetry(3, 2, errors.New("boom"))
	r.Connected(3, "17.253.17.207:443")
	if len(captured.Entries) != 2 {
		t.Fatalf("apex received %d entries without a sink, want 2: %+v", len(captured.Entries), captured.Entries)
	}
	if captured.Entries[0].Level != log.WarnLevel || captured.Entries[1].Level != log.DebugLevel {
		t.Fatalf("severities lost without a sink: %+v", captured.Entries)
	}

	// A live sink takes both records so the redraw survives.
	var sink bytes.Buffer
	setProgressSink(&sink)
	defer clearProgressSink(&sink)
	r.ChunkRetry(3, 3, errors.New("boom"))
	r.Connected(3, "17.253.17.207:443")
	if len(captured.Entries) != 2 {
		t.Fatalf("apex received %d entries with a sink active, want 2: %+v", len(captured.Entries), captured.Entries)
	}
	if out := sink.String(); !strings.Contains(out, "part 03 retry #3: boom") || !strings.Contains(out, "part 03 connected to 17.253.17.207:443") {
		t.Fatalf("sink output = %q, want retry and connected lines", out)
	}
}
