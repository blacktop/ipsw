package handlers

import (
	"context"
	"fmt"
	"sort"

	"github.com/blacktop/ipsw/internal/diff/pipeline"
	"github.com/blacktop/ipsw/internal/search"
	"github.com/blacktop/ipsw/internal/utils"
)

// FileDiff represents file differences between IPSWs.
type FileDiff struct {
	New     map[string][]string `json:"new,omitempty"`
	Removed map[string][]string `json:"removed,omitempty"`
}

// FilesHandler diffs file listings between two IPSWs.
//
// Lists all files from all DMGs and compares.
type FilesHandler struct{}

// Name returns the handler name for logging and results.
func (h *FilesHandler) Name() string {
	return "Files"
}

// DMGTypes returns the DMG types needed by this handler.
// Files handler scans the FileSystem DMG.
func (h *FilesHandler) DMGTypes() []pipeline.DMGType {
	return []pipeline.DMGType{pipeline.DMGTypeFileSystem}
}

// Enabled returns whether this handler should run.
// Only runs if --files flag is provided.
func (h *FilesHandler) Enabled(cfg *pipeline.Config) bool {
	return cfg.Files
}

// Execute runs the files diff operation.
func (h *FilesHandler) Execute(ctx context.Context, exec *pipeline.Executor) (*pipeline.Result, error) {
	result := &pipeline.Result{
		HandlerName: h.Name(),
		Metadata:    make(map[string]any),
	}

	diff := &FileDiff{
		New:     make(map[string][]string),
		Removed: make(map[string][]string),
	}

	// Collect old files
	prev := make(map[string][]string)
	if err := search.ForEachFileInIPSW(
		exec.OldCtx.IPSWPath,
		"",
		exec.Config.PemDB,
		func(dmg, path string) error {
			prev[dmg] = append(prev[dmg], path)
			return nil
		}); err != nil {
		return nil, fmt.Errorf("failed to scan old IPSW files: %w", err)
	}

	// Collect new files
	next := make(map[string][]string)
	if err := search.ForEachFileInIPSW(
		exec.NewCtx.IPSWPath,
		"",
		exec.Config.PemDB,
		func(dmg, path string) error {
			next[dmg] = append(next[dmg], path)
			return nil
		}); err != nil {
		return nil, fmt.Errorf("failed to scan new IPSW files: %w", err)
	}

	// Compute differences per DMG
	for dmg := range prev {
		diff.New[dmg] = utils.Difference(next[dmg], prev[dmg])
		diff.Removed[dmg] = utils.Difference(prev[dmg], next[dmg])
		sort.Strings(diff.New[dmg])
		sort.Strings(diff.Removed[dmg])
	}

	result.Data = diff
	return result, nil
}
