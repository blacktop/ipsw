package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/blacktop/go-macho"
	cstypes "github.com/blacktop/go-macho/pkg/codesign/types"
	"github.com/blacktop/ipsw/internal/commands/ent"
	"github.com/blacktop/ipsw/internal/diff/pipeline"
)

// LaunchConstraintsHandler diffs MachO launch constraints between two IPSWs.
type LaunchConstraintsHandler struct {
	oldExtra map[string]string
	newExtra map[string]string
}

func (h *LaunchConstraintsHandler) Name() string {
	return "Launch Constraints"
}

func (h *LaunchConstraintsHandler) DMGTypes() []pipeline.DMGType {
	return []pipeline.DMGType{
		pipeline.DMGTypeSystemOS,
		pipeline.DMGTypeFileSystem,
		pipeline.DMGTypeAppOS,
		pipeline.DMGTypeExclave,
	}
}

func (h *LaunchConstraintsHandler) Enabled(cfg *pipeline.Config) bool {
	return true
}

func (h *LaunchConstraintsHandler) FileSubscriptions() []pipeline.FileSubscription {
	subs := []pipeline.FileSubscription{{ID: "launch-constraints-zip", Source: pipeline.SourceZIP}}
	for _, dmg := range []pipeline.DMGType{
		pipeline.DMGTypeSystemOS,
		pipeline.DMGTypeFileSystem,
		pipeline.DMGTypeAppOS,
		pipeline.DMGTypeExclave,
	} {
		d := dmg
		subs = append(subs, pipeline.FileSubscription{
			ID:      fmt.Sprintf("launch-constraints-%s", d),
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

func (h *LaunchConstraintsHandler) HandleFile(ctx context.Context, exec *pipeline.Executor, subID string, event *pipeline.FileEvent) error {
	if event == nil || event.Source != pipeline.SourceZIP {
		return nil
	}
	return h.captureZipLaunchConstraints(event)
}

func (h *LaunchConstraintsHandler) Execute(ctx context.Context, exec *pipeline.Executor) (*pipeline.Result, error) {
	result := &pipeline.Result{
		HandlerName: h.Name(),
		Metadata:    make(map[string]any),
	}

	oldDB := h.extractConstraints(exec.OldCtx.MachoCache)
	newDB := h.extractConstraints(exec.NewCtx.MachoCache)

	for path, txt := range h.oldExtra {
		oldDB[path] = txt
	}
	for path, txt := range h.newExtra {
		newDB[path] = txt
	}

	if len(oldDB) == 0 && len(newDB) == 0 {
		result.Data = ""
		return result, nil
	}

	diff, err := ent.DiffDatabases(oldDB, newDB, &ent.Config{
		Markdown: true,
		Color:    false,
		DiffTool: "git",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to diff launch constraints: %w", err)
	}

	h.oldExtra = nil
	h.newExtra = nil
	result.Data = diff
	return result, nil
}

func (h *LaunchConstraintsHandler) extractConstraints(cache *pipeline.MachoCache) map[string]string {
	constraints := make(map[string]string)

	for path, metadata := range cache.All() {
		if len(metadata.LaunchConstraints) == 0 {
			continue
		}

		var builder strings.Builder

		if val := metadata.LaunchConstraints[pipeline.LaunchConstraintSelfKey]; val != "" {
			builder.WriteString("<!-- Launch Constraints (Self) -->\n")
			builder.WriteString(val)
			builder.WriteString("\n")
		}
		if val := metadata.LaunchConstraints[pipeline.LaunchConstraintParentKey]; val != "" {
			builder.WriteString("<!-- Launch Constraints (Parent) -->\n")
			builder.WriteString(val)
			builder.WriteString("\n")
		}
		if val := metadata.LaunchConstraints[pipeline.LaunchConstraintResponsibleKey]; val != "" {
			builder.WriteString("<!-- Launch Constraints (Responsible) -->\n")
			builder.WriteString(val)
			builder.WriteString("\n")
		}

		if builder.Len() > 0 {
			constraints[path] = builder.String()
		}
	}

	return constraints
}

func (h *LaunchConstraintsHandler) captureZipLaunchConstraints(event *pipeline.FileEvent) error {
	data, err := event.ReadAll()
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", event.RelPath, err)
	}
	m, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	defer m.Close()
	cs := m.CodeSignature()
	if cs == nil {
		return nil
	}
	text := serializeLaunchConstraints(cs.LaunchConstraintsSelf, cs.LaunchConstraintsParent, cs.LaunchConstraintsResponsible)
	if text == "" {
		return nil
	}
	bucket := h.lcBucket(event.Side)
	bucket[event.RelPath] = text
	return nil
}

func serializeLaunchConstraints(self, parent, resp []byte) string {
	var builder strings.Builder
	appendLC := func(label string, data []byte) {
		if len(data) == 0 {
			return
		}
		lc, err := cstypes.ParseLaunchContraints(data)
		if err != nil {
			return
		}
		serialized, err := json.MarshalIndent(lc, "", "  ")
		if err != nil {
			return
		}
		builder.WriteString(label)
		builder.WriteByte('\n')
		builder.Write(serialized)
		builder.WriteByte('\n')
	}
	appendLC("<!-- Launch Constraints (Self) -->", self)
	appendLC("<!-- Launch Constraints (Parent) -->", parent)
	appendLC("<!-- Launch Constraints (Responsible) -->", resp)
	return builder.String()
}

func (h *LaunchConstraintsHandler) lcBucket(side pipeline.DiffSide) map[string]string {
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
