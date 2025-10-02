package handlers

import (
	"context"
	"fmt"
	"maps"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	kcmd "github.com/blacktop/ipsw/internal/commands/kernel"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/diff/pipeline"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/blacktop/ipsw/pkg/signature"
)

// KernelcacheHandler diffs kernelcaches between two IPSWs.
//
// Extracts kernelcaches from IPSWs, compares versions, and diffs kexts.
// Supports optional signature symbolication for better symbol names.
type KernelcacheHandler struct{}

// Name returns the handler name for logging and results.
func (h *KernelcacheHandler) Name() string {
	return "Kernelcache"
}

// DMGTypes returns the DMG types needed by this handler.
// Kernelcache is extracted directly from the IPSW zip, no mounting needed.
func (h *KernelcacheHandler) DMGTypes() []pipeline.DMGType {
	return []pipeline.DMGType{pipeline.DMGTypeNone}
}

// Enabled returns whether this handler should run.
// Kernelcache diffing is always enabled.
func (h *KernelcacheHandler) Enabled(cfg *pipeline.Config) bool {
	return true
}

// Execute runs the kernelcache diff operation.
func (h *KernelcacheHandler) Execute(ctx context.Context, exec *pipeline.Executor) (*pipeline.Result, error) {
	result := &pipeline.Result{
		HandlerName: h.Name(),
		Metadata:    make(map[string]any),
	}

	// Extract kernelcaches from both IPSWs
	oldKernelPath, oldVersion, err := h.extractKernelcache(exec.OldCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to extract old kernelcache: %w", err)
	}

	newKernelPath, newVersion, err := h.extractKernelcache(exec.NewCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to extract new kernelcache: %w", err)
	}

	result.Metadata["old_version"] = oldVersion
	result.Metadata["new_version"] = newVersion
	result.Metadata["old_path"] = oldKernelPath
	result.Metadata["new_path"] = newKernelPath

	// Open kernelcache MachOs
	m1, err := macho.Open(oldKernelPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open old kernelcache: %w", err)
	}
	defer m1.Close()

	m2, err := macho.Open(newKernelPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open new kernelcache: %w", err)
	}
	defer m2.Close()

	// Symbolicate if signatures provided
	var smap map[string]signature.SymbolMap
	if exec.Config.Signatures != "" {
		smap, err = h.symbolicate(m1, m2, oldKernelPath, newKernelPath, exec.Config.Signatures)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Errorf("symbolication failed: %w", err))
		}
	}

	// Diff kexts
	log.Info("Diffing kernelcache kexts")
	kexts, err := kcmd.Diff(m1, m2, &mcmd.DiffConfig{
		Markdown:   true,
		Color:      false,
		DiffTool:   "git",
		AllowList:  exec.Config.AllowList,
		BlockList:  exec.Config.BlockList,
		CStrings:   exec.Config.CStrings,
		FuncStarts: exec.Config.FuncStarts,
		SymMap:     smap,
		Verbose:    exec.Config.Verbose,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to diff kernelcache: %w", err)
	}

	result.Data = kexts
	return result, nil
}

// extractKernelcache extracts the kernelcache from an IPSW and returns its path and version.
func (h *KernelcacheHandler) extractKernelcache(ctx *pipeline.Context) (string, *kernelcache.Version, error) {
	var kernelPath string

	// Handle macOS vs iOS differently
	if ctx.Info.Plists.BuildManifest.SupportedProductTypes[0] == "Mac" {
		// macOS: extract with specific device model
		out, err := kernelcache.Extract(ctx.IPSWPath, ctx.Folder, "Macmini9,1")
		if err != nil {
			return "", nil, fmt.Errorf("failed to extract macOS kernelcache: %w", err)
		}
		// Convert iterator to slice and get first key
		var keys []string
		for k := range maps.Keys(out) {
			keys = append(keys, k)
		}
		if len(keys) == 0 {
			return "", nil, fmt.Errorf("no kernelcache extracted")
		}
		kernelPath = keys[0]
	} else {
		// iOS: extract and find first matching kernelcache
		if _, err := kernelcache.Extract(ctx.IPSWPath, ctx.Folder, ""); err != nil {
			return "", nil, fmt.Errorf("failed to extract iOS kernelcache: %w", err)
		}

		// Find first kernelcache model
		kernelcaches := ctx.Info.Plists.GetKernelCaches()
		if len(kernelcaches) == 0 {
			return "", nil, fmt.Errorf("no kernelcaches found in IPSW")
		}

		// Use first kernelcache (handles most common case)
		for kmodel := range kernelcaches {
			if len(kernelcaches[kmodel]) == 0 {
				continue
			}
			kcache := kernelcaches[kmodel][0]
			kernelPath = filepath.Join(ctx.Folder, ctx.Info.GetKernelCacheFileName(kcache))
			break
		}
	}

	if kernelPath == "" {
		return "", nil, fmt.Errorf("failed to determine kernelcache path")
	}

	// Get kernel version
	m, err := macho.Open(kernelPath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to open kernelcache: %w", err)
	}
	defer m.Close()

	version, err := kernelcache.GetVersion(m)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get kernelcache version: %w", err)
	}

	return kernelPath, version, nil
}

// symbolicate creates symbol maps from signature files for better symbol names.
func (h *KernelcacheHandler) symbolicate(m1, m2 *macho.File, oldPath, newPath, sigPath string) (map[string]signature.SymbolMap, error) {
	log.Info("Parsing kernel signatures")
	sigs, err := signature.Parse(sigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signatures: %w", err)
	}

	smap := make(map[string]signature.SymbolMap)

	// Symbolicate old kernelcache
	smap[m1.UUID().String()] = signature.NewSymbolMap()
	log.WithField("kernelcache", oldPath).Info("Symbolicating old kernelcache")
	if err := smap[m1.UUID().String()].Symbolicate(oldPath, sigs, true); err != nil {
		return nil, fmt.Errorf("failed to symbolicate old kernelcache: %w", err)
	}

	// Symbolicate new kernelcache
	smap[m2.UUID().String()] = signature.NewSymbolMap()
	log.WithField("kernelcache", newPath).Info("Symbolicating new kernelcache")
	if err := smap[m2.UUID().String()].Symbolicate(newPath, sigs, true); err != nil {
		return nil, fmt.Errorf("failed to symbolicate new kernelcache: %w", err)
	}

	return smap, nil
}
