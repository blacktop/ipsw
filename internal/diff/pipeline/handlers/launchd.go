package handlers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/diff/pipeline"
	"github.com/blacktop/ipsw/internal/utils"
)

var launchdPathPattern = regexp.MustCompile(`^/sbin/launchd$`)

// LaunchdHandler diffs launchd configuration plists between two IPSWs.
//
// Extracts launchd configs from IPSWs and generates a git diff.
type LaunchdHandler struct {
	oldConfig string
	newConfig string
}

// Name returns the handler name for logging and results.
func (h *LaunchdHandler) Name() string {
	return "Launchd"
}

// DMGTypes returns the DMG types needed by this handler.
// Launchd binary is in /sbin/launchd which is in the FileSystem DMG.
func (h *LaunchdHandler) DMGTypes() []pipeline.DMGType {
	return []pipeline.DMGType{pipeline.DMGTypeFileSystem}
}

// Enabled returns whether this handler should run.
// Only runs if --launchd flag is provided.
func (h *LaunchdHandler) Enabled(cfg *pipeline.Config) bool {
	return cfg.LaunchD
}

// FileSubscriptions registers interest in /sbin/launchd within the FileSystem DMG.
func (h *LaunchdHandler) FileSubscriptions() []pipeline.FileSubscription {
	return []pipeline.FileSubscription{
		{
			ID:          "launchd",
			Source:      pipeline.SourceDMG,
			DMGType:     pipeline.DMGTypeFileSystem,
			PathPattern: launchdPathPattern,
		},
	}
}

// HandleFile captures the launchd config for the matching side.
func (h *LaunchdHandler) HandleFile(ctx context.Context, exec *pipeline.Executor, subID string, event *pipeline.FileEvent) error {
	config, err := readLaunchdConfig(event.AbsPath)
	if err != nil {
		return fmt.Errorf("failed to parse launchd config from %s: %w", event.AbsPath, err)
	}

	if event.Side == pipeline.SideOld {
		h.oldConfig = config
	} else {
		h.newConfig = config
	}
	return nil
}

// Execute runs the launchd config diff operation.
func (h *LaunchdHandler) Execute(ctx context.Context, exec *pipeline.Executor) (*pipeline.Result, error) {
	result := &pipeline.Result{
		HandlerName: h.Name(),
		Metadata:    make(map[string]any),
	}

	if h.oldConfig == "" || h.newConfig == "" {
		return nil, fmt.Errorf("missing launchd config data (old empty=%t new empty=%t)", h.oldConfig == "", h.newConfig == "")
	}

	// Generate git diff
	out, err := utils.GitDiff(
		h.oldConfig+"\n",
		h.newConfig+"\n",
		&utils.GitDiffConfig{Color: false, Tool: "git"})
	if err != nil {
		return nil, fmt.Errorf("failed to diff launchd configs: %w", err)
	}

	// Only include diff if there are changes
	if len(out) > 0 {
		result.Data = "```diff\n" + out + "\n```"
	} else {
		result.Data = "" // No changes
	}

	h.oldConfig = ""
	h.newConfig = ""

	return result, nil
}

func readLaunchdConfig(path string) (string, error) {
	var (
		m      *macho.File
		closer io.Closer
		err    error
	)

	if fat, ferr := macho.OpenFat(path); ferr == nil {
		m = fat.Arches[len(fat.Arches)-1].File
		closer = fat
	} else {
		if !errors.Is(ferr, macho.ErrNotFat) {
			return "", fmt.Errorf("failed to open macho file: %w", ferr)
		}
		m, err = macho.Open(path)
		if err != nil {
			return "", fmt.Errorf("failed to open macho file: %w", err)
		}
		closer = m
	}
	defer closer.Close()

	section := m.Section("__TEXT", "__config")
	if section == nil {
		return "", fmt.Errorf("launchd missing __TEXT.__config section")
	}

	data, err := section.Data()
	if err != nil {
		return "", fmt.Errorf("failed to get launchd config: %w", err)
	}

	return string(data), nil
}
