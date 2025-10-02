package handlers

import (
	"context"
	"fmt"

	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/diff/pipeline"
)

// FirmwareHandler diffs firmware files between two IPSWs.
//
// Extracts and compares firmware MachO files from IPSWs.
type FirmwareHandler struct{}

// Name returns the handler name for logging and results.
func (h *FirmwareHandler) Name() string {
	return "Firmware"
}

// DMGTypes returns the DMG types needed by this handler.
// Firmware files are extracted directly from the IPSW zip, no mounting needed.
func (h *FirmwareHandler) DMGTypes() []pipeline.DMGType {
	return []pipeline.DMGType{pipeline.DMGTypeNone}
}

// Enabled returns whether this handler should run.
// Only runs if --firmware flag is provided.
func (h *FirmwareHandler) Enabled(cfg *pipeline.Config) bool {
	return cfg.Firmware
}

// Execute runs the firmware diff operation.
func (h *FirmwareHandler) Execute(ctx context.Context, exec *pipeline.Executor) (*pipeline.Result, error) {
	result := &pipeline.Result{
		HandlerName: h.Name(),
		Metadata:    make(map[string]any),
	}

	// Diff firmware files
	firmwares, err := mcmd.DiffFirmwares(
		exec.OldCtx.IPSWPath,
		exec.NewCtx.IPSWPath,
		&mcmd.DiffConfig{
			Markdown:   true,
			Color:      false,
			DiffTool:   "git",
			AllowList:  exec.Config.AllowList,
			BlockList:  exec.Config.BlockList,
			CStrings:   exec.Config.CStrings,
			FuncStarts: exec.Config.FuncStarts,
			Verbose:    exec.Config.Verbose,
		})
	if err != nil {
		return nil, fmt.Errorf("failed to diff firmwares: %w", err)
	}

	result.Data = firmwares
	return result, nil
}
