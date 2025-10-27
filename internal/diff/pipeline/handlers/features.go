package handlers

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/blacktop/ipsw/internal/diff/pipeline"
	"github.com/blacktop/ipsw/internal/utils"
)

// PlistDiff represents differences in plist files.
type PlistDiff struct {
	New     map[string]string `json:"new,omitempty"`
	Removed []string          `json:"removed,omitempty"`
	Updated map[string]string `json:"changed,omitempty"`
}

// FeaturesHandler diffs feature flags plists between two IPSWs.
//
// Searches for feature flags in /System/Library/FeatureFlags across all DMGs.
type FeaturesHandler struct {
	oldPlists map[string]string
	newPlists map[string]string
}

// Name returns the handler name for logging and results.
func (h *FeaturesHandler) Name() string {
	return "Features"
}

// DMGTypes returns the DMG types needed by this handler.
// Feature flags are in /System/Library/FeatureFlags which is in the FileSystem DMG.
func (h *FeaturesHandler) DMGTypes() []pipeline.DMGType {
	return []pipeline.DMGType{pipeline.DMGTypeFileSystem}
}

// Enabled returns whether this handler should run.
// Only runs if --features flag is provided.
func (h *FeaturesHandler) Enabled(cfg *pipeline.Config) bool {
	return cfg.Features
}

// FileSubscriptions registers interest in FeatureFlags plists inside FileSystem DMG.
func (h *FeaturesHandler) FileSubscriptions() []pipeline.FileSubscription {
	return []pipeline.FileSubscription{
		{
			ID:          "feature-plists",
			Source:      pipeline.SourceDMG,
			DMGType:     pipeline.DMGTypeFileSystem,
			PathPattern: regexp.MustCompile(`^/System/Library/FeatureFlags/.*\.plist$`),
		},
	}
}

// HandleFile captures plist contents for old/new sides.
func (h *FeaturesHandler) HandleFile(ctx context.Context, exec *pipeline.Executor, subID string, event *pipeline.FileEvent) error {
	data, err := event.ReadAll()
	if err != nil {
		return fmt.Errorf("failed to read feature flag %s: %w", event.RelPath, err)
	}

	if event.Side == pipeline.SideOld {
		if h.oldPlists == nil {
			h.oldPlists = make(map[string]string)
		}
		h.oldPlists[event.RelPath] = string(data)
	} else {
		if h.newPlists == nil {
			h.newPlists = make(map[string]string)
		}
		h.newPlists[event.RelPath] = string(data)
	}
	return nil
}

// Execute runs the feature flags diff operation.
func (h *FeaturesHandler) Execute(ctx context.Context, exec *pipeline.Executor) (*pipeline.Result, error) {
	result := &pipeline.Result{
		HandlerName: h.Name(),
		Metadata:    make(map[string]any),
	}

	diff := &PlistDiff{
		New:     make(map[string]string),
		Updated: make(map[string]string),
	}

	oldPlists := h.oldPlists
	if oldPlists == nil {
		oldPlists = make(map[string]string)
	}

	newPlists := h.newPlists
	if newPlists == nil {
		newPlists = make(map[string]string)
	}

	// Get sorted file lists
	var prevFiles []string
	for f := range oldPlists {
		prevFiles = append(prevFiles, f)
	}
	slices.Sort(prevFiles)

	var nextFiles []string
	for f := range newPlists {
		nextFiles = append(nextFiles, f)
	}
	slices.Sort(nextFiles)

	// Find new and removed files
	newFiles := utils.Difference(nextFiles, prevFiles)
	diff.Removed = utils.Difference(prevFiles, nextFiles)

	// Compare plists
	for _, f2 := range nextFiles {
		// Entirely new file
		if slices.Contains(newFiles, f2) {
			diff.New[f2] = newPlists[f2]
			continue
		}

		// Check for changes
		dat2 := newPlists[f2]
		if dat1, ok := oldPlists[f2]; ok {
			if strings.EqualFold(dat2, dat1) {
				continue // No changes
			}

			// Generate diff
			out, err := utils.GitDiff(
				dat1+"\n",
				dat2+"\n",
				&utils.GitDiffConfig{Color: false, Tool: "git"})
			if err != nil {
				return nil, fmt.Errorf("failed to diff %s: %w", f2, err)
			}

			if len(out) > 0 {
				diff.Updated[f2] = "```diff\n" + out + "\n```"
			}
		}
	}

	h.oldPlists = nil
	h.newPlists = nil

	result.Data = diff
	return result, nil
}
