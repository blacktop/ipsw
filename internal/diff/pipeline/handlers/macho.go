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
// MachO files are in all DMGs: SystemOS, FileSystem, AppOS, and Exclave.
func (h *MachOHandler) DMGTypes() []pipeline.DMGType {
	return []pipeline.DMGType{
		pipeline.DMGTypeSystemOS,
		pipeline.DMGTypeFileSystem,
		pipeline.DMGTypeAppOS,
		pipeline.DMGTypeExclave,
	}
}

// Enabled returns whether this handler should run.
// MachO handler always runs (no explicit flag, it's a core diff operation).
func (h *MachOHandler) Enabled(cfg *pipeline.Config) bool {
	return true
}

// FileSubscriptions ensures all DMG walkers run so MachO metadata
// gets cached while the DMGs are mounted. We rely on Executor.maybeCacheMachO
// to do the heavy lifting before these callbacks fire.
func (h *MachOHandler) FileSubscriptions() []pipeline.FileSubscription {
	matchFunc := func(evt *pipeline.FileEvent) bool {
		if evt == nil || evt.Ctx == nil {
			return false
		}
		_, ok := evt.Ctx.MachoCache.Get(evt.RelPath)
		return ok
	}

	var subs []pipeline.FileSubscription
	for _, dmgType := range []pipeline.DMGType{
		pipeline.DMGTypeSystemOS,
		pipeline.DMGTypeFileSystem,
		pipeline.DMGTypeAppOS,
		pipeline.DMGTypeExclave,
	} {
		dt := dmgType // capture for closure
		subs = append(subs, pipeline.FileSubscription{
			ID:        fmt.Sprintf("macho-cache-%d", dt),
			Source:    pipeline.SourceDMG,
			DMGType:   dt,
			MatchFunc: matchFunc,
		})
	}

	return subs
}

// HandleFile currently acts as a no-op because metadata is already inserted
// into the cache by the executor's streaming walker.
func (h *MachOHandler) HandleFile(ctx context.Context, exec *pipeline.Executor, subID string, event *pipeline.FileEvent) error {
	return nil
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

		imports := metadata.Imports

		var sections []mcmd.Section
		if len(metadata.Sections) > 0 {
			sections = make([]mcmd.Section, len(metadata.Sections))
			for i, sec := range metadata.Sections {
				sections[i] = mcmd.Section{
					Name: sec.Name,
					Size: sec.Size,
				}
			}
		}

		diffInfo := &mcmd.DiffInfo{
			Version:   metadata.Version,
			UUID:      metadata.UUID,
			Imports:   imports,
			Sections:  sections,
			Functions: metadata.Functions,
			Symbols:   metadata.Symbols,
			CStrings:  metadata.CStrings,
			SymbolMap: make(map[uint64]string),
			Verbose:   cfg.Verbose,
		}

		if cfg.FuncStarts && len(metadata.FunctionStarts) > 0 {
			diffInfo.Starts = metadata.FunctionStarts
			diffInfo.Functions = len(metadata.FunctionStarts)
			if len(metadata.SymbolMap) > 0 {
				diffInfo.SymbolMap = metadata.SymbolMap
			}
		}

		diffInfoMap[path] = diffInfo
	}

	return diffInfoMap
}
