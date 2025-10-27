package handlers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/blacktop/ipsw/internal/diff/pipeline"
	"github.com/blacktop/ipsw/internal/utils"
)

// FileDiff represents file differences between IPSWs.
type FileDiff struct {
	New     map[string][]string `json:"new,omitempty"`
	Removed map[string][]string `json:"removed,omitempty"`
}

// FilesHandler diffs file listings between two IPSWs.
type FilesHandler struct {
	old map[string][]string
	new map[string][]string
}

// Name returns the handler name for logging and results.
func (h *FilesHandler) Name() string {
	return "Files"
}

// DMGTypes returns the DMG types needed by this handler.
func (h *FilesHandler) DMGTypes() []pipeline.DMGType {
	return []pipeline.DMGType{
		pipeline.DMGTypeFileSystem,
		pipeline.DMGTypeSystemOS,
		pipeline.DMGTypeAppOS,
		pipeline.DMGTypeExclave,
	}
}

// Enabled returns whether this handler should run.
func (h *FilesHandler) Enabled(cfg *pipeline.Config) bool {
	return cfg.Files
}

var dmgEntryPattern = regexp.MustCompile(`[0-9]{3}-[0-9]{5}-[0-9]{3}\.dmg(\.aea|\.trustcache)?(\.root_hash|\.trustcache|\.integrity_catalog|\.mtree)?$`)

// FileSubscriptions lets the handler receive per-file callbacks.
func (h *FilesHandler) FileSubscriptions() []pipeline.FileSubscription {
	return []pipeline.FileSubscription{
		{ID: "zip", Source: pipeline.SourceZIP},
	}
}

// HandleFile records the file path for the corresponding side/DMG.
func (h *FilesHandler) HandleFile(ctx context.Context, exec *pipeline.Executor, subID string, event *pipeline.FileEvent) error {
	if event == nil || event.Source != pipeline.SourceZIP {
		return nil
	}
	if dmgEntryPattern.MatchString(event.RelPath) {
		return nil
	}

	label := filesLabelForEvent(event)
	bucket := h.bucket(event.Side)
	path := filepath.ToSlash(event.RelPath)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	bucket[label] = append(bucket[label], path)
	return nil
}

// Execute runs after all file events have been processed and produces the diff.
func (h *FilesHandler) Execute(ctx context.Context, exec *pipeline.Executor) (*pipeline.Result, error) {
	result := &pipeline.Result{
		HandlerName: h.Name(),
		Metadata:    make(map[string]any),
	}

	if err := h.collectDMGFiles(ctx, exec, exec.OldCtx, pipeline.SideOld); err != nil {
		return nil, err
	}
	if err := h.collectDMGFiles(ctx, exec, exec.NewCtx, pipeline.SideNew); err != nil {
		return nil, err
	}

	diff := &FileDiff{
		New:     make(map[string][]string),
		Removed: make(map[string][]string),
	}

	labels := make(map[string]struct{})
	for label := range h.old {
		labels[label] = struct{}{}
	}
	for label := range h.new {
		labels[label] = struct{}{}
	}

	for label := range labels {
		added := utils.Difference(h.sorted(h.new[label]), h.sorted(h.old[label]))
		removed := utils.Difference(h.sorted(h.old[label]), h.sorted(h.new[label]))
		sort.Strings(added)
		sort.Strings(removed)
		diff.New[label] = added
		diff.Removed[label] = removed
	}

	// reset state for potential reuse (e.g., tests)
	h.old = nil
	h.new = nil

	result.Data = diff
	return result, nil
}

func (h *FilesHandler) bucket(side pipeline.DiffSide) map[string][]string {
	if side == pipeline.SideOld {
		if h.old == nil {
			h.old = make(map[string][]string)
		}
		return h.old
	}

	if h.new == nil {
		h.new = make(map[string][]string)
	}
	return h.new
}

func (h *FilesHandler) sorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	cloned := append([]string(nil), values...)
	sort.Strings(cloned)
	return cloned
}

func filesLabelForEvent(evt *pipeline.FileEvent) string {
	if evt.Source == pipeline.SourceZIP {
		return "IPSW"
	}

	return filesLabelForDMGType(evt.DMGType)
}

func filesLabelForDMGType(dmgType pipeline.DMGType) string {
	switch dmgType {
	case pipeline.DMGTypeFileSystem:
		return "filesystem"
	case pipeline.DMGTypeSystemOS:
		return "SystemOS"
	case pipeline.DMGTypeAppOS:
		return "AppOS"
	case pipeline.DMGTypeExclave:
		return "ExclaveOS"
	default:
		return dmgType.String()
	}
}

func (h *FilesHandler) collectDMGFiles(ctx context.Context, exec *pipeline.Executor, ipswCtx *pipeline.Context, side pipeline.DiffSide) error {
	for _, dmgType := range h.DMGTypes() {
		label := filesLabelForDMGType(dmgType)
		if label == "" {
			continue
		}
		if err := exec.WalkDMGFiles(ctx, ipswCtx, dmgType, func(relPath, _ string, _ os.FileInfo) error {
			bucket := h.bucket(side)
			bucket[label] = append(bucket[label], relPath)
			return nil
		}); err != nil {
			return fmt.Errorf("failed to enumerate %s files for %s: %w", label, ipswCtx.IPSWPath, err)
		}
	}
	return nil
}
