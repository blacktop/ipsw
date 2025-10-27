package handlers

import (
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"

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
type KernelcacheHandler struct {
	oldFile    string
	newFile    string
	oldRel     string
	newRel     string
	oldTargets map[string]struct{}
	newTargets map[string]struct{}
}

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

var kernelcacheRegex = regexp.MustCompile(`(?i)kernelcache`)

func (h *KernelcacheHandler) FileSubscriptions() []pipeline.FileSubscription {
	return []pipeline.FileSubscription{
		{
			ID:     "kernelcache",
			Source: pipeline.SourceZIP,
			MatchFunc: func(evt *pipeline.FileEvent) bool {
				return kernelcacheRegex.MatchString(evt.RelPath)
			},
		},
	}
}

func (h *KernelcacheHandler) HandleFile(ctx context.Context, exec *pipeline.Executor, subID string, event *pipeline.FileEvent) error {
	if event == nil || event.Ctx == nil {
		return nil
	}
	if event.Side == pipeline.SideOld && h.oldFile != "" {
		return nil
	}
	if event.Side == pipeline.SideNew && h.newFile != "" {
		return nil
	}
	targets := h.targetsFor(event.Side, event.Ctx)
	if len(targets) > 0 {
		if _, ok := targets[event.RelPath]; !ok {
			return nil
		}
	} else if !kernelcacheRegex.MatchString(event.RelPath) {
		return nil
	}

	tmp, err := os.CreateTemp("", "ipsw_kernelcache")
	if err != nil {
		return fmt.Errorf("failed to create temp kernelcache: %w", err)
	}
	r, err := event.Open()
	if err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return fmt.Errorf("failed to open kernelcache entry %s: %w", event.RelPath, err)
	}
	if _, err := io.Copy(tmp, r); err != nil {
		r.Close()
		tmp.Close()
		os.Remove(tmp.Name())
		return fmt.Errorf("failed to copy kernelcache %s: %w", event.RelPath, err)
	}
	r.Close()
	tmp.Close()

	if event.Side == pipeline.SideOld {
		h.oldFile = tmp.Name()
		h.oldRel = event.RelPath
	} else {
		h.newFile = tmp.Name()
		h.newRel = event.RelPath
	}
	return nil
}

// Execute runs the kernelcache diff operation.
func (h *KernelcacheHandler) Execute(ctx context.Context, exec *pipeline.Executor) (*pipeline.Result, error) {
	result := &pipeline.Result{
		HandlerName: h.Name(),
		Metadata:    make(map[string]any),
	}

	// Resolve kernelcaches
	oldKernelPath, oldVersion, oldCleanup, err := h.resolveKernelcache(pipeline.SideOld, exec.OldCtx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if oldCleanup {
			os.Remove(oldKernelPath)
			h.oldFile = ""
		}
	}()

	newKernelPath, newVersion, newCleanup, err := h.resolveKernelcache(pipeline.SideNew, exec.NewCtx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if newCleanup {
			os.Remove(newKernelPath)
			h.newFile = ""
		}
	}()

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

func (h *KernelcacheHandler) resolveKernelcache(side pipeline.DiffSide, ctx *pipeline.Context) (string, *kernelcache.Version, bool, error) {
	var path string
	var rel string
	switch side {
	case pipeline.SideOld:
		path = h.oldFile
		rel = h.oldRel
	case pipeline.SideNew:
		path = h.newFile
		rel = h.newRel
	}

	if path == "" {
		legacyPath, version, cleanup, err := h.extractKernelcache(ctx)
		return legacyPath, version, cleanup, err
	}

	version, err := h.kernelcacheVersion(path)
	if err != nil {
		return "", nil, true, err
	}
	if rel != "" {
		if side == pipeline.SideOld {
			log.Infof("Captured kernelcache from %s", rel)
		} else {
			log.Infof("Captured kernelcache from %s", rel)
		}
	}
	return path, version, true, nil
}

func (h *KernelcacheHandler) kernelcacheVersion(path string) (*kernelcache.Version, error) {
	m, err := macho.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open kernelcache %s: %w", path, err)
	}
	defer m.Close()
	version, err := kernelcache.GetVersion(m)
	if err != nil {
		return nil, fmt.Errorf("failed to get kernelcache version from %s: %w", path, err)
	}
	return version, nil
}

// fallback extraction (legacy)
func (h *KernelcacheHandler) extractKernelcache(ctx *pipeline.Context) (string, *kernelcache.Version, bool, error) {
	var kernelPath string

	if len(ctx.Info.Plists.BuildManifest.SupportedProductTypes) > 0 && ctx.Info.Plists.BuildManifest.SupportedProductTypes[0] == "Mac" {
		out, err := kernelcache.Extract(ctx.IPSWPath, ctx.Folder, "Macmini9,1")
		if err != nil {
			return "", nil, false, fmt.Errorf("failed to extract macOS kernelcache: %w", err)
		}
		var keys []string
		for k := range maps.Keys(out) {
			keys = append(keys, k)
		}
		if len(keys) == 0 {
			return "", nil, false, fmt.Errorf("no kernelcache extracted")
		}
		kernelPath = keys[0]
	} else {
		if _, err := kernelcache.Extract(ctx.IPSWPath, ctx.Folder, ""); err != nil {
			return "", nil, false, fmt.Errorf("failed to extract iOS kernelcache: %w", err)
		}
		kernelcaches := ctx.Info.Plists.GetKernelCaches()
		if len(kernelcaches) == 0 {
			return "", nil, false, fmt.Errorf("no kernelcaches found in IPSW")
		}
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
		return "", nil, false, fmt.Errorf("failed to determine kernelcache path")
	}

	version, err := h.kernelcacheVersion(kernelPath)
	if err != nil {
		return "", nil, false, err
	}

	return kernelPath, version, false, nil
}

func (h *KernelcacheHandler) targetsFor(side pipeline.DiffSide, ctx *pipeline.Context) map[string]struct{} {
	if ctx == nil || ctx.Info == nil {
		return nil
	}
	switch side {
	case pipeline.SideOld:
		if h.oldTargets == nil {
			h.oldTargets = buildKernelcacheTargets(ctx)
		}
		return h.oldTargets
	default:
		if h.newTargets == nil {
			h.newTargets = buildKernelcacheTargets(ctx)
		}
		return h.newTargets
	}
}

func buildKernelcacheTargets(ctx *pipeline.Context) map[string]struct{} {
	targets := make(map[string]struct{})
	kernelcaches := ctx.Info.Plists.GetKernelCaches()
	if len(kernelcaches) == 0 {
		return targets
	}
	for _, entries := range kernelcaches {
		if len(entries) == 0 {
			continue
		}
		kc := entries[0]
		path := filepath.ToSlash(ctx.Info.GetKernelCacheFileName(kc))
		targets[path] = struct{}{}
		break
	}
	return targets
}
