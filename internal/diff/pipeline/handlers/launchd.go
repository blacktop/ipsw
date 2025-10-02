package handlers

import (
	"context"
	"fmt"

	"github.com/blacktop/ipsw/internal/commands/extract"
	"github.com/blacktop/ipsw/internal/diff/pipeline"
	"github.com/blacktop/ipsw/internal/utils"
)

// LaunchdHandler diffs launchd configuration plists between two IPSWs.
//
// Extracts launchd configs from IPSWs and generates a git diff.
type LaunchdHandler struct{}

// Name returns the handler name for logging and results.
func (h *LaunchdHandler) Name() string {
	return "Launchd"
}

// DMGTypes returns the DMG types needed by this handler.
// Launchd binary is in /sbin/launchd which is in the FileSystem DMG.
func (h *LaunchdHandler) DMGTypes() []pipeline.DMGType {
	return []pipeline.DMGType{pipeline.DMGTypeFileSystem}
}

// Enabled returns whether this handler should run.
// Only runs if --launchd flag is provided.
func (h *LaunchdHandler) Enabled(cfg *pipeline.Config) bool {
	return cfg.LaunchD
}

// Execute runs the launchd config diff operation.
func (h *LaunchdHandler) Execute(ctx context.Context, exec *pipeline.Executor) (*pipeline.Result, error) {
	result := &pipeline.Result{
		HandlerName: h.Name(),
		Metadata:    make(map[string]any),
	}

	// Extract old launchd config
	oldConfig, err := extract.LaunchdConfig(exec.OldCtx.IPSWPath, exec.Config.PemDB)
	if err != nil {
		return nil, fmt.Errorf("failed to get old launchd config: %w", err)
	}

	// Extract new launchd config
	newConfig, err := extract.LaunchdConfig(exec.NewCtx.IPSWPath, exec.Config.PemDB)
	if err != nil {
		return nil, fmt.Errorf("failed to get new launchd config: %w", err)
	}

	// Generate git diff
	out, err := utils.GitDiff(
		string(oldConfig)+"\n",
		string(newConfig)+"\n",
		&utils.GitDiffConfig{Color: false, Tool: "git"})
	if err != nil {
		return nil, fmt.Errorf("failed to diff launchd configs: %w", err)
	}

	// Only include diff if there are changes
	if len(out) > 0 {
		result.Data = "```diff\n" + out + "\n```"
	} else {
		result.Data = "" // No changes
	}

	return result, nil
}
