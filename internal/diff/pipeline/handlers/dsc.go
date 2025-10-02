// Package handlers contains handler implementations for the diff pipeline.
package handlers

import (
	"context"
	"fmt"
	"regexp"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/diff/pipeline"
	dcmd "github.com/blacktop/ipsw/internal/commands/dsc"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/pkg/dyld"
)

// DSCHandler diffs dyld_shared_cache between two IPSWs.
//
// The dyld_shared_cache contains prelinked system libraries and frameworks.
// This handler compares the dylibs between old and new caches, extracts
// WebKit versions, and reports changes in library exports/imports.
type DSCHandler struct{}

// NewDSCHandler creates a new DSC diff handler.
func NewDSCHandler() *DSCHandler {
	return &DSCHandler{}
}

func (h *DSCHandler) Name() string {
	return "DYLD Shared Cache"
}

func (h *DSCHandler) DMGTypes() []pipeline.DMGType {
	return []pipeline.DMGType{pipeline.DMGTypeSystemOS}
}

func (h *DSCHandler) Enabled(cfg *pipeline.Config) bool {
	// DSC is always enabled (core functionality)
	return true
}

func (h *DSCHandler) Execute(ctx context.Context, exec *pipeline.Executor) (*pipeline.Result, error) {
	result := &pipeline.Result{
		HandlerName: h.Name(),
		Metadata:    make(map[string]any),
	}

	// Get old DSC
	oldMount, ok := exec.OldCtx.GetMount(pipeline.DMGTypeSystemOS)
	if !ok {
		return nil, fmt.Errorf("SystemOS not mounted for old IPSW")
	}

	oldDSCs, err := h.findDSCs(oldMount.MountPath, exec.OldCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to find old DSCs: %w", err)
	}

	dscOld, err := dyld.Open(oldDSCs[0])
	if err != nil {
		return nil, fmt.Errorf("failed to open old DSC: %w", err)
	}
	defer dscOld.Close()

	// Get new DSC
	newMount, ok := exec.NewCtx.GetMount(pipeline.DMGTypeSystemOS)
	if !ok {
		return nil, fmt.Errorf("SystemOS not mounted for new IPSW")
	}

	newDSCs, err := h.findDSCs(newMount.MountPath, exec.NewCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to find new DSCs: %w", err)
	}

	dscNew, err := dyld.Open(newDSCs[0])
	if err != nil {
		return nil, fmt.Errorf("failed to open new DSC: %w", err)
	}
	defer dscNew.Close()

	// Get WebKit versions
	oldWebKit, err := dcmd.GetWebkitVersion(dscOld)
	if err != nil {
		log.WithError(err).Warn("Failed to get old WebKit version")
		result.Warnings = append(result.Warnings, fmt.Errorf("old webkit: %w", err))
	} else {
		result.Metadata["webkit_old"] = oldWebKit
	}

	newWebKit, err := dcmd.GetWebkitVersion(dscNew)
	if err != nil {
		log.WithError(err).Warn("Failed to get new WebKit version")
		result.Warnings = append(result.Warnings, fmt.Errorf("new webkit: %w", err))
	} else {
		result.Metadata["webkit_new"] = newWebKit
	}

	// Diff dylibs
	dylibDiff, err := dcmd.Diff(dscOld, dscNew, &mcmd.DiffConfig{
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
		return nil, fmt.Errorf("failed to diff DSCs: %w", err)
	}

	result.Data = dylibDiff
	result.Metadata["dsc_old"] = oldDSCs[0]
	result.Metadata["dsc_new"] = newDSCs[0]

	return result, nil
}

// findDSCs locates dyld_shared_cache files in the mounted DMG.
func (h *DSCHandler) findDSCs(mountPath string, ctx *pipeline.Context) ([]string, error) {
	dscs, err := dyld.GetDscPathsInMount(mountPath, false, false)
	if err != nil {
		return nil, err
	}
	if len(dscs) == 0 {
		return nil, fmt.Errorf("no DSCs found in %s", mountPath)
	}

	// Filter for macOS arm64e
	if ctx.Info.IsMacOS() {
		var filtered []string
		r := regexp.MustCompile(fmt.Sprintf("%s(%s)%s", dyld.CacheRegex, "arm64e", dyld.CacheRegexEnding))
		for _, match := range dscs {
			if r.MatchString(match) {
				filtered = append(filtered, match)
			}
		}
		if len(filtered) == 0 {
			return nil, fmt.Errorf("no arm64e DSCs found")
		}
		return filtered, nil
	}

	return dscs, nil
}
