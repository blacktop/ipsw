package handlers

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/blacktop/ipsw/internal/commands/dwarf"
	"github.com/blacktop/ipsw/internal/diff/pipeline"
)

// KDKHandler diffs KDK DWARF structures between two kernel binaries.
//
// Compares kernel data structure definitions from KDK debug symbols.
// Only enabled when both KDKs are provided via the --kdk flag.
type KDKHandler struct{}

// Name returns the handler name for logging and results.
func (h *KDKHandler) Name() string {
	return "KDK"
}

// DMGTypes returns the DMG types needed by this handler.
// KDK handler works with external KDK files, not from IPSWs.
func (h *KDKHandler) DMGTypes() []pipeline.DMGType {
	return []pipeline.DMGType{pipeline.DMGTypeNone}
}

// Enabled returns whether this handler should run.
// Only runs if both KDKs are provided.
func (h *KDKHandler) Enabled(cfg *pipeline.Config) bool {
	// KDKs are set on the contexts, not in config
	// Executor will check if both KDKs exist before running
	return true // Let executor decide based on context
}

// Execute runs the KDK DWARF structure diff operation.
func (h *KDKHandler) Execute(ctx context.Context, exec *pipeline.Executor) (*pipeline.Result, error) {
	result := &pipeline.Result{
		HandlerName: h.Name(),
		Metadata:    make(map[string]any),
	}

	// Check if both KDKs are provided
	if exec.OldCtx.KDK == "" || exec.NewCtx.KDK == "" {
		// Skip silently - not an error, just not enabled
		return result, nil
	}

	// Normalize KDK paths to point to DWARF files
	oldKDK := h.normalizePath(exec.OldCtx.KDK)
	newKDK := h.normalizePath(exec.NewCtx.KDK)

	// Diff DWARF structures
	diff, err := dwarf.DiffStructures(oldKDK, newKDK, &dwarf.Config{
		Markdown: true,
		Color:    false,
		DiffTool: "git",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to diff KDK structures: %w", err)
	}

	result.Data = diff

	// Store normalized KDK names for display
	result.Metadata["old_kdk"] = h.extractKDKName(oldKDK)
	result.Metadata["new_kdk"] = h.extractKDKName(newKDK)

	return result, nil
}

// normalizePath ensures the KDK path points to the DWARF file.
// If path doesn't contain DWARF directory, constructs it.
func (h *KDKHandler) normalizePath(kdkPath string) string {
	if strings.Contains(kdkPath, ".dSYM/Contents/Resources/DWARF") {
		return kdkPath
	}
	return filepath.Join(kdkPath+".dSYM/Contents/Resources/DWARF", filepath.Base(kdkPath))
}

// extractKDKName extracts the KDK name from the full path for display.
// Removes /Library/Developer/KDKs/ prefix and .dSYM/Contents/Resources/DWARF suffix.
func (h *KDKHandler) extractKDKName(kdkPath string) string {
	name := strings.TrimPrefix(kdkPath, "/Library/Developer/KDKs/")
	name, _, _ = strings.Cut(name, ".dSYM/Contents/Resources/DWARF")
	return name
}
