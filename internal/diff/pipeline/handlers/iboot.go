package handlers

import (
	"archive/zip"
	"context"
	"fmt"
	"os"
	"regexp"

	"github.com/blacktop/ipsw/internal/diff/pipeline"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/iboot"
	"github.com/blacktop/ipsw/pkg/img4"
)

// IBootDiff represents the differences between two iBoot versions.
type IBootDiff struct {
	Versions []string            `json:"versions,omitempty"`
	New      map[string][]string `json:"new,omitempty"`
	Removed  map[string][]string `json:"removed,omitempty"`
}

// IBootHandler diffs iBoot strings between two IPSWs.
//
// Extracts iBoot im4p files, parses strings, and compares.
type IBootHandler struct{}

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

// Execute runs the iBoot diff operation.
func (h *IBootHandler) Execute(ctx context.Context, exec *pipeline.Executor) (*pipeline.Result, error) {
	result := &pipeline.Result{
		HandlerName: h.Name(),
		Metadata:    make(map[string]any),
	}

	// Create temp directory for im4p extraction
	tmpDIR, err := os.MkdirTemp("", "ipsw_extract_iboot")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDIR)

	// Extract iBoot from both IPSWs
	oldIBoot, err := h.extractIBoot(exec.OldCtx.IPSWPath, tmpDIR)
	if err != nil {
		return nil, fmt.Errorf("failed to extract old iBoot: %w", err)
	}

	newIBoot, err := h.extractIBoot(exec.NewCtx.IPSWPath, tmpDIR)
	if err != nil {
		return nil, fmt.Errorf("failed to extract new iBoot: %w", err)
	}

	// Create diff structure
	diff := &IBootDiff{
		Versions: []string{oldIBoot.Version, newIBoot.Version},
		New:      make(map[string][]string),
		Removed:  make(map[string][]string),
	}

	// Find new strings
	for name, strs := range newIBoot.Strings {
		if oldStrs, ok := oldIBoot.Strings[name]; ok {
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
	for name, strs := range oldIBoot.Strings {
		if newStrs, ok := newIBoot.Strings[name]; ok {
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
	return result, nil
}

// extractIBoot extracts and parses iBoot from an IPSW.
func (h *IBootHandler) extractIBoot(ipswPath, tmpDIR string) (*iboot.IBoot, error) {
	// Extract iBoot im4p file
	iBootIm4ps, err := utils.Unzip(ipswPath, tmpDIR, func(f *zip.File) bool {
		return regexp.MustCompile(`iBoot\..*\.im4p$`).MatchString(f.Name)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to unzip iBoot im4p: %w", err)
	}
	if len(iBootIm4ps) == 0 {
		return nil, fmt.Errorf("no iBoot im4p found in IPSW")
	}

	// Open im4p payload
	im4p, err := img4.OpenPayload(iBootIm4ps[0])
	if err != nil {
		return nil, fmt.Errorf("failed to open im4p: %w", err)
	}

	// Parse iBoot
	ib, err := iboot.Parse(im4p.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse iBoot: %w", err)
	}

	return ib, nil
}
