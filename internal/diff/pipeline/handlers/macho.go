package handlers

import (
	"context"
	"fmt"

	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/diff/pipeline"
)

// MachOHandler diffs all MachO files between two IPSWs using the cache.
//
// This handler reads from the pre-populated MachO cache instead of scanning
// files directly, eliminating redundant parsing and reducing memory usage.
type MachOHandler struct{}

// Name returns the handler name for logging and results.
func (h *MachOHandler) Name() string {
	return "MachO"
}

// DMGTypes returns the DMG types needed by this handler.
// MachO files are in the SystemOS DMG.
func (h *MachOHandler) DMGTypes() []pipeline.DMGType {
	return []pipeline.DMGType{pipeline.DMGTypeSystemOS}
}

// Enabled returns whether this handler should run.
// MachO handler always runs (no explicit flag, it's a core diff operation).
func (h *MachOHandler) Enabled(cfg *pipeline.Config) bool {
	return true
}

// Execute runs the MachO diff operation using cached data.
func (h *MachOHandler) Execute(ctx context.Context, exec *pipeline.Executor) (*pipeline.Result, error) {
	result := &pipeline.Result{
		HandlerName: h.Name(),
		Metadata:    make(map[string]any),
	}

	// Convert cache to DiffInfo maps
	oldDiffInfo := h.cacheToDiffInfo(exec.OldCtx.MachoCache, exec.Config)
	newDiffInfo := h.cacheToDiffInfo(exec.NewCtx.MachoCache, exec.Config)

	// Generate diff using existing logic
	diff := &mcmd.MachoDiff{
		Updated: make(map[string]string),
	}

	if err := diff.Generate(oldDiffInfo, newDiffInfo, &mcmd.DiffConfig{
		Markdown:   true,
		Color:      false,
		DiffTool:   "git",
		AllowList:  exec.Config.AllowList,
		BlockList:  exec.Config.BlockList,
		CStrings:   exec.Config.CStrings,
		FuncStarts: exec.Config.FuncStarts,
		Verbose:    exec.Config.Verbose,
	}); err != nil {
		return nil, fmt.Errorf("failed to generate MachO diff: %w", err)
	}

	result.Data = diff
	return result, nil
}

// cacheToDiffInfo converts cached MachO metadata to DiffInfo format.
//
// Note: This creates a simplified DiffInfo from cache data. Some fields like
// function start addresses are not available from the cache and are left empty.
// This is acceptable because the cache-based approach prioritizes memory efficiency
// over complete function-level diffing.
func (h *MachOHandler) cacheToDiffInfo(cache *pipeline.MachoCache, cfg *pipeline.Config) map[string]*mcmd.DiffInfo {
	diffInfoMap := make(map[string]*mcmd.DiffInfo)

	for path, metadata := range cache.All() {
		// Skip files that failed to parse
		if metadata.ParseError != nil {
			continue
		}

		// Create DiffInfo with available cached data
		// Note: We can't populate the Sections field because it uses an
		// unexported type. The diff will still work based on other fields.
		diffInfo := &mcmd.DiffInfo{
			Version:   metadata.Version,
			UUID:      metadata.UUID,
			Imports:   metadata.LoadCommands,
			Sections:  nil, // Cannot populate due to unexported section type
			Functions: metadata.Functions,
			Starts:    nil, // Function start details not in cache
			Symbols:   metadata.Symbols,
			CStrings:  metadata.CStrings,
			SymbolMap: make(map[uint64]string),
			Verbose:   cfg.Verbose,
		}

		diffInfoMap[path] = diffInfo
	}

	return diffInfoMap
}
