//go:build wallpaper

package tui

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blacktop/ipsw/pkg/wallpaper"
)

func newTestWallpaperModel() *model {
	ctx, cancel := context.WithCancel(context.Background())
	return &model{ctx: ctx, cancel: cancel}
}

func TestWallpaperCloseWaitsForCanceledPreview(t *testing.T) {
	m := newTestWallpaperModel()
	if !m.beginPreview() {
		t.Fatal("beginPreview() = false before Close")
	}
	var finished atomic.Bool
	go func() {
		<-m.ctx.Done()
		time.Sleep(50 * time.Millisecond)
		finished.Store(true)
		m.previews.Done()
	}()

	m.Close()

	if !finished.Load() {
		t.Fatal("Close returned before the canceled preview finished")
	}
	if m.beginPreview() {
		t.Fatal("beginPreview() = true after Close")
	}
	asset := wallpaper.WallpaperAsset{BaseURL: "https://example.invalid/", RelativePath: "wp.zip"}
	if msg := m.previewWallpaperCmd(asset, 0)(); msg != nil {
		t.Fatalf("preview after Close returned %#v, want nil", msg)
	}
}

func TestWallpaperCloseGivesUpOnStuckPreview(t *testing.T) {
	m := newTestWallpaperModel()
	if !m.beginPreview() {
		t.Fatal("beginPreview() = false before Close")
	}
	t.Cleanup(m.previews.Done)

	start := time.Now()
	m.Close()
	elapsed := time.Since(start)

	if elapsed < previewShutdownGrace || elapsed > previewShutdownGrace+time.Second {
		t.Fatalf("Close took %v, want about %v", elapsed, previewShutdownGrace)
	}
}
