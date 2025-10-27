package handlers

import (
	"bytes"
	"context"
	"fmt"

	"github.com/blacktop/go-macho"
	ents "github.com/blacktop/ipsw/internal/codesign/entitlements"
	"github.com/blacktop/ipsw/internal/commands/ent"
	"github.com/blacktop/ipsw/internal/diff/pipeline"
)

// EntitlementsHandler diffs entitlements databases between two IPSWs.
//
// Reads entitlements from the pre-populated MachO cache instead of scanning
// files directly, eliminating redundant parsing.
type EntitlementsHandler struct {
	oldExtra map[string]string
	newExtra map[string]string
}

// Name returns the handler name for logging and results.
func (h *EntitlementsHandler) Name() string {
	return "Entitlements"
}

// DMGTypes returns the DMG types needed by this handler.
// Entitlements are extracted from MachO files in SystemOS DMG.
func (h *EntitlementsHandler) DMGTypes() []pipeline.DMGType {
	return []pipeline.DMGType{
		pipeline.DMGTypeSystemOS,
		pipeline.DMGTypeFileSystem,
		pipeline.DMGTypeAppOS,
		pipeline.DMGTypeExclave,
	}
}

// Enabled returns whether this handler should run.
// Only runs if --entitlements flag is provided.
func (h *EntitlementsHandler) Enabled(cfg *pipeline.Config) bool {
	return cfg.Entitlements
}

// FileSubscriptions ensure the walkers fire for all DMGs and ZIP entries.
func (h *EntitlementsHandler) FileSubscriptions() []pipeline.FileSubscription {
	subs := []pipeline.FileSubscription{
		{ID: "entitlements-zip", Source: pipeline.SourceZIP},
	}
	for _, dmg := range []pipeline.DMGType{
		pipeline.DMGTypeSystemOS,
		pipeline.DMGTypeFileSystem,
		pipeline.DMGTypeAppOS,
		pipeline.DMGTypeExclave,
	} {
		d := dmg
		subs = append(subs, pipeline.FileSubscription{
			ID:      fmt.Sprintf("entitlements-%s", d),
			Source:  pipeline.SourceDMG,
			DMGType: d,
			MatchFunc: func(evt *pipeline.FileEvent) bool {
				if evt == nil || evt.Ctx == nil {
					return false
				}
				_, ok := evt.Ctx.MachoCache.Get(evt.RelPath)
				return ok
			},
		})
	}
	return subs
}

func (h *EntitlementsHandler) HandleFile(ctx context.Context, exec *pipeline.Executor, subID string, event *pipeline.FileEvent) error {
	if event == nil {
		return nil
	}
	if event.Source != pipeline.SourceZIP {
		return nil
	}
	return h.captureZipEntitlements(event)
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

	for path, xml := range h.oldExtra {
		oldDB[path] = xml
	}
	for path, xml := range h.newExtra {
		newDB[path] = xml
	}

	oldMeta := exec.OldCtx.MachoCache.All()
	newMeta := exec.NewCtx.MachoCache.All()

	h.ensurePlaceholderEntries(oldDB, oldMeta, newMeta)
	h.ensurePlaceholderEntries(newDB, newMeta, oldMeta)

	// Diff databases using existing logic
	diff, err := ent.DiffDatabases(oldDB, newDB, &ent.Config{
		Markdown: true,
		Color:    false,
		DiffTool: "git",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to diff entitlements: %w", err)
	}

	h.oldExtra = nil
	h.newExtra = nil

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

func (h *EntitlementsHandler) captureZipEntitlements(event *pipeline.FileEvent) error {
	data, err := event.ReadAll()
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", event.RelPath, err)
	}
	m, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil // not a MachO, ignore
	}
	defer m.Close()
	cs := m.CodeSignature()
	if cs == nil {
		return nil
	}
	entXML := ""
	switch {
	case len(cs.Entitlements) > 0:
		entXML = cs.Entitlements
	case len(cs.EntitlementsDER) > 0:
		if decoded, derr := ents.DerDecode(cs.EntitlementsDER); derr == nil {
			entXML = decoded
		} else {
			return fmt.Errorf("failed to decode DER entitlements from %s: %w", event.RelPath, derr)
		}
	default:
		return nil
	}

	if entXML == "" {
		return nil
	}

	bucket := h.extraBucket(event.Side)
	bucket[event.RelPath] = entXML
	return nil
}

func (h *EntitlementsHandler) extraBucket(side pipeline.DiffSide) map[string]string {
	if side == pipeline.SideOld {
		if h.oldExtra == nil {
			h.oldExtra = make(map[string]string)
		}
		return h.oldExtra
	}
	if h.newExtra == nil {
		h.newExtra = make(map[string]string)
	}
	return h.newExtra
}

func (h *EntitlementsHandler) ensurePlaceholderEntries(target map[string]string, primary, other map[string]*pipeline.MachoMetadata) {
	for path, metadata := range primary {
		if metadata == nil || metadata.ParseError != nil {
			continue
		}
		if _, ok := target[path]; ok {
			continue
		}
		if _, exists := other[path]; exists {
			continue
		}
		target[path] = ""
	}
}
