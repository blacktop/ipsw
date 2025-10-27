// Package handlers contains handler implementations for the diff pipeline.
package handlers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/apex/log"
	dcmd "github.com/blacktop/ipsw/internal/commands/dsc"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/diff/pipeline"
	"github.com/blacktop/ipsw/pkg/dyld"
)

var (
	dscPathRegex     = regexp.MustCompile(fmt.Sprintf(`%s(%s)%s`, dyld.CacheUberRegex, "arm64e", `$`))
	macArm64ePattern = regexp.MustCompile(fmt.Sprintf(`%s(%s)%s`, dyld.CacheUberRegex, "arm64e", `$`))
)

// DSCHandler diffs dyld_shared_cache between two IPSWs.
//
// The dyld_shared_cache contains prelinked system libraries and frameworks.
// This handler compares the dylibs between old and new caches, extracts
// WebKit versions, and reports changes in library exports/imports.
//
// It analyzes both the main system DSC and secondary DSCs (like DriverKit).
type DSCHandler struct {
	oldPaths []string
	newPaths []string
}

// DSCDiffResult holds the diff results for a specific DSC type.
type DSCDiffResult struct {
	Type       string // "system" or "driverkit"
	OldPath    string
	NewPath    string
	WebKitOld  string
	WebKitNew  string
	DylibDiff  *mcmd.MachoDiff
	ImageCount int // number of images in the cache
}

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

func (h *DSCHandler) FileSubscriptions() []pipeline.FileSubscription {
	return []pipeline.FileSubscription{
		{
			ID:          "dsc",
			Source:      pipeline.SourceDMG,
			DMGType:     pipeline.DMGTypeSystemOS,
			PathPattern: dscPathRegex,
		},
	}
}

func (h *DSCHandler) HandleFile(ctx context.Context, exec *pipeline.Executor, subID string, event *pipeline.FileEvent) error {
	if event.Side == pipeline.SideOld {
		h.oldPaths = append(h.oldPaths, event.AbsPath)
	} else {
		h.newPaths = append(h.newPaths, event.AbsPath)
	}
	return nil
}

func (h *DSCHandler) Execute(ctx context.Context, exec *pipeline.Executor) (*pipeline.Result, error) {
	result := &pipeline.Result{
		HandlerName: h.Name(),
		Metadata:    make(map[string]any),
	}

	var err error
	if h.oldPaths, err = h.ensureDSCPaths(exec.OldCtx, h.oldPaths); err != nil {
		return nil, fmt.Errorf("old DSC: %w", err)
	}
	if h.newPaths, err = h.ensureDSCPaths(exec.NewCtx, h.newPaths); err != nil {
		return nil, fmt.Errorf("new DSC: %w", err)
	}

	// Analyze main system DSC
	systemResult, err := h.analyzeDSC(ctx, exec, h.oldPaths, h.newPaths, "system")
	if err != nil {
		return nil, fmt.Errorf("main system DSC: %w", err)
	}

	// Analyze DriverKit DSC if available
	driverKitResult, err := h.analyzeDSC(ctx, exec, h.oldPaths, h.newPaths, "driverkit")
	if err != nil {
		// DriverKit is optional, just log the warning
		log.WithError(err).Debug("DriverKit DSC not available or failed to analyze")
	}

	// Combine results
	results := []DSCDiffResult{systemResult}
	if driverKitResult.DylibDiff != nil {
		results = append(results, driverKitResult)
	}

	// Set primary (system) DSC metadata for backward compatibility
	result.Metadata["webkit_old"] = systemResult.WebKitOld
	result.Metadata["webkit_new"] = systemResult.WebKitNew
	result.Metadata["dsc_old"] = systemResult.OldPath
	result.Metadata["dsc_new"] = systemResult.NewPath
	result.Data = results

	h.oldPaths = nil
	h.newPaths = nil

	return result, nil
}

// analyzeDSC analyzes a specific DSC type (system or driverkit).
func (h *DSCHandler) analyzeDSC(ctx context.Context, exec *pipeline.Executor, oldPaths, newPaths []string, dscType string) (DSCDiffResult, error) {
	var emptyResult DSCDiffResult

	oldPath, err := h.pickDSCByType(exec.OldCtx, oldPaths, dscType)
	if err != nil {
		return emptyResult, fmt.Errorf("old %s DSC: %w", dscType, err)
	}
	newPath, err := h.pickDSCByType(exec.NewCtx, newPaths, dscType)
	if err != nil {
		return emptyResult, fmt.Errorf("new %s DSC: %w", dscType, err)
	}

	dscOld, err := dyld.Open(oldPath)
	if err != nil {
		return emptyResult, fmt.Errorf("failed to open old %s DSC: %w", dscType, err)
	}
	defer dscOld.Close()

	dscNew, err := dyld.Open(newPath)
	if err != nil {
		return emptyResult, fmt.Errorf("failed to open new %s DSC: %w", dscType, err)
	}
	defer dscNew.Close()

	diffResult := DSCDiffResult{
		Type:       dscType,
		OldPath:    oldPath,
		NewPath:    newPath,
		ImageCount: len(dscOld.Images),
	}

	// Get WebKit versions (only for main system DSC)
	if dscType == "system" {
		oldWebKit, err := dcmd.GetWebkitVersion(dscOld)
		if err != nil {
			log.WithError(err).Warnf("Failed to get old WebKit version (cache: %s)", oldPath)
		} else {
			diffResult.WebKitOld = oldWebKit
		}

		newWebKit, err := dcmd.GetWebkitVersion(dscNew)
		if err != nil {
			log.WithError(err).Warnf("Failed to get new WebKit version (cache: %s)", newPath)
		} else {
			diffResult.WebKitNew = newWebKit
		}
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
		return emptyResult, fmt.Errorf("failed to diff %s DSCs: %w", dscType, err)
	}

	diffResult.DylibDiff = dylibDiff

	return diffResult, nil
}

// pickDSCByType selects the appropriate DSC based on type (system or driverkit).
func (h *DSCHandler) pickDSCByType(ctx *pipeline.Context, paths []string, dscType string) (string, error) {
	if len(paths) == 0 {
		return "", fmt.Errorf("no DSCs captured")
	}

	switch dscType {
	case "system":
		return h.pickSystemDSC(paths)
	case "driverkit":
		return h.pickDriverKitDSC(paths)
	default:
		return "", fmt.Errorf("unknown DSC type: %s", dscType)
	}
}

// pickSystemDSC selects the main system DSC, excluding DriverKit and other specialized caches.
func (h *DSCHandler) pickSystemDSC(paths []string) (string, error) {
	// Exclude DriverKit and other specialized caches - we want the main system DSC
	exclude := func(p string) bool {
		return strings.Contains(p, "/DriverKit/") ||
			strings.Contains(p, "/Cryptexes/")
	}

	prefer := func(p string) bool {
		if exclude(p) {
			return false
		}
		return strings.Contains(p, "/System/Library/dyld/") || strings.Contains(p, "/System/Library/Caches/com.apple.dyld/")
	}

	// prefer system/root caches first
	for _, path := range paths {
		if prefer(path) && macArm64ePattern.MatchString(path) {
			return path, nil
		}
	}
	for _, path := range paths {
		if prefer(path) {
			return path, nil
		}
	}

	// fallback to whichever non-excluded cache we captured first
	for _, path := range paths {
		if !exclude(path) {
			return path, nil
		}
	}

	return "", fmt.Errorf("no system DSC found")
}

// pickDriverKitDSC selects the DriverKit DSC.
func (h *DSCHandler) pickDriverKitDSC(paths []string) (string, error) {
	// Look for DriverKit DSC
	for _, path := range paths {
		if strings.Contains(path, "/DriverKit/") && macArm64ePattern.MatchString(path) {
			return path, nil
		}
	}
	for _, path := range paths {
		if strings.Contains(path, "/DriverKit/") {
			return path, nil
		}
	}

	return "", fmt.Errorf("no DriverKit DSC found")
}

// pickDSC is kept for potential backward compatibility but delegates to pickSystemDSC.
func (h *DSCHandler) pickDSC(ctx *pipeline.Context, paths []string) (string, error) {
	return h.pickSystemDSC(paths)
}

func (h *DSCHandler) ensureDSCPaths(ctx *pipeline.Context, existing []string) ([]string, error) {
	if len(existing) > 0 {
		return existing, nil
	}
	paths, err := h.findDSCPaths(ctx)
	if err != nil {
		return nil, err
	}
	return paths, nil
}

func (h *DSCHandler) findDSCPaths(ctx *pipeline.Context) ([]string, error) {
	mount, ok := ctx.GetMount(pipeline.DMGTypeSystemOS)
	if !ok || mount == nil || mount.MountPath == "" {
		return nil, fmt.Errorf("SystemOS mount unavailable")
	}

	searchRoots := []string{
		filepath.Join(mount.MountPath, "System/Library/Caches/com.apple.dyld"),
		filepath.Join(mount.MountPath, "System/Library/dyld"),
	}

	var matches []string
	for _, root := range searchRoots {
		glob := filepath.Join(root, "dyld_shared_cache*")
		files, err := filepath.Glob(glob)
		if err != nil {
			return nil, fmt.Errorf("glob %s: %w", glob, err)
		}
		for _, f := range files {
			info, err := os.Stat(f)
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			matches = append(matches, f)
		}
	}

	if len(matches) == 0 {
		return nil, fmt.Errorf("no dyld_shared_cache files found under %s", mount.MountPath)
	}

	return matches, nil
}
