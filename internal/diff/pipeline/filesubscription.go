package pipeline

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"context"
)

// SourceKind identifies where a file event originates from.
type SourceKind int

const (
	// SourceZIP represents a file that lives directly inside the IPSW zip.
	SourceZIP SourceKind = iota
	// SourceDMG represents a file that originates from a mounted DMG.
	SourceDMG
)

// DiffSide indicates whether the event belongs to the "old" or "new" IPSW.
type DiffSide int

const (
	SideOld DiffSide = iota
	SideNew
)

// FileSubscription declares interest in files encountered during ZIP or DMG walks.
type FileSubscription struct {
	// ID is an optional identifier to disambiguate multiple subscriptions
	// from a single handler.
	ID string
	// Source indicates whether this subscription applies to the IPSW zip or a DMG.
	Source SourceKind
	// DMGType filters DMG events; ignored for ZIP subscriptions.
	DMGType DMGType
	// PathPattern restricts matches to paths that satisfy the regex.
	PathPattern *regexp.Regexp
	// MatchFunc provides custom matching logic. If nil, only PathPattern is evaluated.
	MatchFunc func(*FileEvent) bool
}

// matches evaluates whether the subscription is interested in the given event.
func (sub FileSubscription) matches(evt *FileEvent) bool {
	if sub.Source != evt.Source {
		return false
	}
	if evt.Source == SourceDMG && sub.DMGType != DMGTypeNone && sub.DMGType != evt.DMGType {
		return false
	}
	if sub.PathPattern != nil && !sub.PathPattern.MatchString(evt.RelPath) {
		return false
	}
	if sub.MatchFunc != nil && !sub.MatchFunc(evt) {
		return false
	}
	return true
}

// FileEvent describes a single file encountered during a walk.
type FileEvent struct {
	Source SourceKind
	Side   DiffSide

	Ctx *Context

	// DMG-specific metadata
	DMGType  DMGType
	MountRef *Mount

	RelPath string // path relative to the zip root or DMG mount root (always slash-separated)
	AbsPath string // absolute on-disk path (DMG only)

	info    os.FileInfo
	zipFile *zip.File
}

// Size returns the file size if available.
func (evt *FileEvent) Size() int64 {
	if evt.zipFile != nil {
		return int64(evt.zipFile.UncompressedSize64)
	}
	if evt.info != nil {
		return evt.info.Size()
	}
	return 0
}

// Open returns a ReadCloser for the file contents.
func (evt *FileEvent) Open() (io.ReadCloser, error) {
	switch evt.Source {
	case SourceZIP:
		if evt.zipFile == nil {
			return nil, fmt.Errorf("zip entry unavailable for %s", evt.RelPath)
		}
		return evt.zipFile.Open()
	case SourceDMG:
		return os.Open(evt.AbsPath) // #nosec G304
	default:
		return nil, fmt.Errorf("unknown source kind")
	}
}

// ReadAll reads the entire file contents into memory.
func (evt *FileEvent) ReadAll() ([]byte, error) {
	r, err := evt.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// FileSubscriber allows handlers to subscribe to file events while DMGs/ZIPs are walked.
type FileSubscriber interface {
	FileSubscriptions() []FileSubscription
	HandleFile(ctx context.Context, exec *Executor, subID string, event *FileEvent) error
}

// subscriptionEntry associates a handler with its subscriptions.
type subscriptionEntry struct {
	handler    Handler
	subscriber FileSubscriber
	subs       []FileSubscription
}

// normalizeRelPath ensures paths are slash-separated and prefixed with '/'.
// It handles symlink resolution (e.g., /tmp -> /private/tmp on macOS).
func normalizeRelPath(base, target string) string {
	// Resolve symlinks in both paths to ensure they match
	// This is important on macOS where /tmp is a symlink to /private/tmp
	if absBase, err := filepath.EvalSymlinks(base); err == nil {
		base = absBase
	}
	if absTarget, err := filepath.EvalSymlinks(target); err == nil {
		target = absTarget
	}

	rel := strings.TrimPrefix(target, base)
	rel = strings.TrimPrefix(rel, string(filepath.Separator))
	if !strings.HasPrefix(rel, "/") {
		rel = "/" + rel
	}
	rel = filepath.ToSlash(rel)
	return rel
}
