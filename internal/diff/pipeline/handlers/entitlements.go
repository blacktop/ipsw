package handlers

import (
	"context"
	"fmt"

	"github.com/blacktop/ipsw/internal/commands/ent"
	"github.com/blacktop/ipsw/internal/diff/pipeline"
)

// EntitlementsHandler diffs entitlements databases between two IPSWs.
//
// Extracts entitlements from all MachO files and compares.
// TODO: This will benefit from MachO cache when implemented.
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

// Execute runs the entitlements diff operation.
func (h *EntitlementsHandler) Execute(ctx context.Context, exec *pipeline.Executor) (*pipeline.Result, error) {
	result := &pipeline.Result{
		HandlerName: h.Name(),
		Metadata:    make(map[string]any),
	}

	// Build old entitlements database
	oldDB, err := ent.GetDatabase(&ent.Config{
		IPSW:              exec.OldCtx.IPSWPath,
		PemDB:             exec.Config.PemDB,
		LaunchConstraints: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get old entitlements database: %w", err)
	}

	// Build new entitlements database
	newDB, err := ent.GetDatabase(&ent.Config{
		IPSW:              exec.NewCtx.IPSWPath,
		PemDB:             exec.Config.PemDB,
		LaunchConstraints: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get new entitlements database: %w", err)
	}

	// Diff databases
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
