package handlers

import (
	"context"
	"fmt"
	"regexp"

	"github.com/blacktop/ipsw/internal/diff/pipeline"
	"github.com/blacktop/ipsw/pkg/iboot"
	"github.com/blacktop/ipsw/pkg/img4"
)

var ibootPathPattern = regexp.MustCompile(`(?i)iBoot\..*\.im4p$`)

// IBootDiff represents the differences between two iBoot versions.
type IBootDiff struct {
	Versions []string            `json:"versions,omitempty"`
	New      map[string][]string `json:"new,omitempty"`
	Removed  map[string][]string `json:"removed,omitempty"`
}

// IBootHandler diffs iBoot strings between two IPSWs.
//
// Extracts iBoot im4p files, parses strings, and compares.
type IBootHandler struct {
	oldIBoot *iboot.IBoot
	newIBoot *iboot.IBoot
}

// Name returns the handler name for logging and results.
func (h *IBootHandler) Name() string {
	return "IBoot"
}

// DMGTypes returns the DMG types needed by this handler.
// iBoot im4p files are extracted directly from the IPSW zip, no mounting needed.
func (h *IBootHandler) DMGTypes() []pipeline.DMGType {
	return []pipeline.DMGType{pipeline.DMGTypeNone}
}

// Enabled returns whether this handler should run.
// Only runs if --firmware flag is provided (iBoot is part of firmware).
func (h *IBootHandler) Enabled(cfg *pipeline.Config) bool {
	return cfg.Firmware
}

func (h *IBootHandler) FileSubscriptions() []pipeline.FileSubscription {
	return []pipeline.FileSubscription{
		{
			ID:          "iboot",
			Source:      pipeline.SourceZIP,
			PathPattern: ibootPathPattern,
		},
	}
}

func (h *IBootHandler) HandleFile(ctx context.Context, exec *pipeline.Executor, subID string, event *pipeline.FileEvent) error {
	data, err := event.ReadAll()
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", event.RelPath, err)
	}
	payload, err := img4.ParsePayload(data)
	if err != nil {
		return fmt.Errorf("failed to parse iBoot payload %s: %w", event.RelPath, err)
	}
	ib, err := iboot.Parse(payload.Data)
	if err != nil {
		return fmt.Errorf("failed to parse iBoot: %w", err)
	}
	if event.Side == pipeline.SideOld {
		h.oldIBoot = ib
	} else {
		h.newIBoot = ib
	}
	return nil
}

// Execute runs the iBoot diff operation.
func (h *IBootHandler) Execute(ctx context.Context, exec *pipeline.Executor) (*pipeline.Result, error) {
	result := &pipeline.Result{
		HandlerName: h.Name(),
		Metadata:    make(map[string]any),
	}

	if h.oldIBoot == nil || h.newIBoot == nil {
		return nil, fmt.Errorf("missing iBoot data (old=%t, new=%t)", h.oldIBoot != nil, h.newIBoot != nil)
	}

	// Create diff structure
	diff := &IBootDiff{
		Versions: []string{h.oldIBoot.Version, h.newIBoot.Version},
		New:      make(map[string][]string),
		Removed:  make(map[string][]string),
	}

	// Find new strings
	for name, strs := range h.newIBoot.Strings {
		if oldStrs, ok := h.oldIBoot.Strings[name]; ok {
			for _, str := range strs {
				if len(str) < 10 {
					continue
				}
				found := false
				for _, oldStr := range oldStrs {
					if str == oldStr {
						found = true
						break
					}
				}
				if !found {
					diff.New[name] = append(diff.New[name], str)
				}
			}
		} else {
			// Entire section is new
			for _, str := range strs {
				diff.New[name] = append(diff.New[name], str)
			}
		}
	}

	// Find removed strings
	for name, strs := range h.oldIBoot.Strings {
		if newStrs, ok := h.newIBoot.Strings[name]; ok {
			for _, str := range strs {
				if len(str) < 10 {
					continue
				}
				found := false
				for _, newStr := range newStrs {
					if str == newStr {
						found = true
						break
					}
				}
				if !found {
					diff.Removed[name] = append(diff.Removed[name], str)
				}
			}
		}
	}

	result.Data = diff
	h.oldIBoot = nil
	h.newIBoot = nil
	return result, nil
}
