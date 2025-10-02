package handlers

import (
	"context"
	"fmt"

	"github.com/blacktop/ipsw/internal/commands/ent"
	"github.com/blacktop/ipsw/internal/diff/pipeline"
)

// EntitlementsHandler diffs entitlements databases between two IPSWs.
//
// Reads entitlements from the pre-populated MachO cache instead of scanning
// files directly, eliminating redundant parsing.
type EntitlementsHandler struct{}

// Name returns the handler name for logging and results.
func (h *EntitlementsHandler) Name() string {
	return "Entitlements"
}

// DMGTypes returns the DMG types needed by this handler.
// Entitlements are extracted from MachO files in SystemOS DMG.
func (h *EntitlementsHandler) DMGTypes() []pipeline.DMGType {
	return []pipeline.DMGType{pipeline.DMGTypeSystemOS}
}

// Enabled returns whether this handler should run.
// Only runs if --entitlements flag is provided.
func (h *EntitlementsHandler) Enabled(cfg *pipeline.Config) bool {
	return cfg.Entitlements
}

// Execute runs the entitlements diff operation using cached data.
func (h *EntitlementsHandler) Execute(ctx context.Context, exec *pipeline.Executor) (*pipeline.Result, error) {
	result := &pipeline.Result{
		HandlerName: h.Name(),
		Metadata:    make(map[string]any),
	}

	// Extract entitlements from cache (no file scanning!)
	oldDB := h.extractEntitlementsFromCache(exec.OldCtx.MachoCache)
	newDB := h.extractEntitlementsFromCache(exec.NewCtx.MachoCache)

	// Diff databases using existing logic
	diff, err := ent.DiffDatabases(oldDB, newDB, &ent.Config{
		Markdown: true,
		Color:    false,
		DiffTool: "git",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to diff entitlements: %w", err)
	}

	result.Data = diff
	return result, nil
}

// extractEntitlementsFromCache builds an entitlements database from cached data.
//
// This eliminates the need to scan MachO files again - we just read the
// entitlements that were already extracted during cache population.
func (h *EntitlementsHandler) extractEntitlementsFromCache(cache *pipeline.MachoCache) map[string]string {
	entDB := make(map[string]string)

	for path, metadata := range cache.All() {
		// Skip files that failed to parse or have no entitlements
		if metadata.ParseError != nil || metadata.Entitlements == "" {
			continue
		}

		entDB[path] = metadata.Entitlements
	}

	return entDB
}
