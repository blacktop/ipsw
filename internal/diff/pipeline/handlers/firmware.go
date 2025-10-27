package handlers

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	fwcmd "github.com/blacktop/ipsw/internal/commands/fw"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/diff/pipeline"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/pkg/ftab"
	"github.com/blacktop/ipsw/pkg/img4"
)

// FirmwareHandler diffs firmware files between two IPSWs using streamed IM4P blobs.
type FirmwareHandler struct {
	old map[string]*mcmd.DiffInfo
	new map[string]*mcmd.DiffInfo
}

// Name returns the handler name for logging and results.
func (h *FirmwareHandler) Name() string {
	return "Firmware"
}

// DMGTypes returns the DMG types needed by this handler.
// Firmware files are extracted directly from the IPSW zip, no mounting needed.
func (h *FirmwareHandler) DMGTypes() []pipeline.DMGType {
	return []pipeline.DMGType{pipeline.DMGTypeNone}
}

// Enabled returns whether this handler should run.
// Only runs if --firmware flag is provided.
func (h *FirmwareHandler) Enabled(cfg *pipeline.Config) bool {
	return cfg.Firmware
}

// Execute runs the firmware diff operation.
var (
	im4pPattern        = regexp.MustCompile(`(?i)\.im4p$`)
	armfwPattern       = regexp.MustCompile(`armfw_.*\.im4p$`)
	exclaveBundleRegex = regexp.MustCompile(`.*exclavecore_bundle.*\.im4p$`)
)

func (h *FirmwareHandler) FileSubscriptions() []pipeline.FileSubscription {
	return []pipeline.FileSubscription{
		{
			ID:          "firmware-im4p",
			Source:      pipeline.SourceZIP,
			PathPattern: im4pPattern,
		},
	}
}

func (h *FirmwareHandler) HandleFile(ctx context.Context, exec *pipeline.Executor, subID string, event *pipeline.FileEvent) error {
	data, err := event.ReadAll()
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", event.RelPath, err)
	}

	conf := &mcmd.DiffConfig{
		Markdown:   true,
		Color:      false,
		DiffTool:   "git",
		AllowList:  exec.Config.AllowList,
		BlockList:  exec.Config.BlockList,
		CStrings:   exec.Config.CStrings,
		FuncStarts: exec.Config.FuncStarts,
		Verbose:    exec.Config.Verbose,
	}

	switch {
	case armfwPattern.MatchString(event.RelPath):
		return h.processArmfw(event, data, conf)
	case exclaveBundleRegex.MatchString(event.RelPath):
		return h.processExclave(event, data, conf)
	default:
		return h.processGeneric(event, data, conf)
	}
}

func (h *FirmwareHandler) Execute(ctx context.Context, exec *pipeline.Executor) (*pipeline.Result, error) {
	result := &pipeline.Result{
		HandlerName: h.Name(),
		Metadata:    make(map[string]any),
	}

	conf := &mcmd.DiffConfig{
		Markdown:   true,
		Color:      false,
		DiffTool:   "git",
		AllowList:  exec.Config.AllowList,
		BlockList:  exec.Config.BlockList,
		CStrings:   exec.Config.CStrings,
		FuncStarts: exec.Config.FuncStarts,
		Verbose:    exec.Config.Verbose,
	}

	diff := &mcmd.MachoDiff{
		Updated: make(map[string]string),
	}

	if err := diff.Generate(h.old, h.new, conf); err != nil {
		return nil, fmt.Errorf("failed to diff firmwares: %w", err)
	}

	// reset for subsequent runs
	h.old = nil
	h.new = nil

	result.Data = diff
	return result, nil
}

func (h *FirmwareHandler) processGeneric(event *pipeline.FileEvent, im4pData []byte, conf *mcmd.DiffConfig) error {
	payload, err := img4.ParsePayload(im4pData)
	if err != nil {
		return fmt.Errorf("failed to parse %s payload: %w", event.RelPath, err)
	}
	data, err := payload.GetData()
	if err != nil {
		return fmt.Errorf("failed to get data from %s: %w", event.RelPath, err)
	}
	isMachO, err := magic.IsMachOData(data)
	if err != nil {
		return fmt.Errorf("failed to inspect %s payload magic: %w", event.RelPath, err)
	}
	if !isMachO {
		log.Debugf("Skipping firmware %s: payload is not a MachO", event.RelPath)
		return nil
	}
	m, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to parse macho from %s: %w", event.RelPath, err)
	}
	defer m.Close()

	info := mcmd.GenerateDiffInfo(m, conf)
	h.addDiffInfo(event.Side, filepath.Base(event.RelPath), info)
	return nil
}

func (h *FirmwareHandler) processArmfw(event *pipeline.FileEvent, im4pData []byte, conf *mcmd.DiffConfig) error {
	payload, err := img4.ParsePayload(im4pData)
	if err != nil {
		return fmt.Errorf("failed to parse %s payload: %w", event.RelPath, err)
	}
	data, err := payload.GetData()
	if err != nil {
		return fmt.Errorf("failed to get data from %s: %w", event.RelPath, err)
	}

	table, err := ftab.Parse(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to parse ftab from %s: %w", event.RelPath, err)
	}
	defer table.Close()

	for _, entry := range table.Entries {
		buf, err := io.ReadAll(entry)
		if err != nil {
			return fmt.Errorf("failed to read ftab entry from %s: %w", event.RelPath, err)
		}
		m, err := macho.NewFile(bytes.NewReader(buf))
		if err != nil {
			continue
		}
		info := mcmd.GenerateDiffInfo(m, conf)
		m.Close()
		name := "agx_" + filepath.Base(string(entry.Tag[:]))
		h.addDiffInfo(event.Side, name, info)
	}
	return nil
}

func (h *FirmwareHandler) processExclave(event *pipeline.FileEvent, im4pData []byte, conf *mcmd.DiffConfig) error {
	payload, err := img4.ParsePayload(im4pData)
	if err != nil {
		return fmt.Errorf("failed to parse %s payload: %w", event.RelPath, err)
	}
	data, err := payload.GetData()
	if err != nil {
		return fmt.Errorf("failed to get data from %s: %w", event.RelPath, err)
	}

	tmpDir, err := os.MkdirTemp("", "ipsw_exclave_fw")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	files, err := fwcmd.ExtractExclaveCores(data, tmpDir)
	if err != nil {
		return fmt.Errorf("failed to extract exclave cores from %s: %w", event.RelPath, err)
	}

	for _, path := range files {
		isMachO, err := magic.IsMachO(path)
		if err != nil {
			return fmt.Errorf("failed to inspect exclave artifact %s: %w", path, err)
		}
		if !isMachO {
			log.Debugf("Skipping exclave artifact %s: not a MachO payload", path)
			continue
		}
		m, err := macho.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open exclave macho %s: %w", path, err)
		}
		info := mcmd.GenerateDiffInfo(m, conf)
		m.Close()
		name := "exclave_" + filepath.Base(path)
		h.addDiffInfo(event.Side, name, info)
	}

	return nil
}

func (h *FirmwareHandler) addDiffInfo(side pipeline.DiffSide, name string, info *mcmd.DiffInfo) {
	if info == nil {
		return
	}
	bucket := h.bucket(side)
	bucket[name] = info
}

func (h *FirmwareHandler) bucket(side pipeline.DiffSide) map[string]*mcmd.DiffInfo {
	if side == pipeline.SideOld {
		if h.old == nil {
			h.old = make(map[string]*mcmd.DiffInfo)
		}
		return h.old
	}
	if h.new == nil {
		h.new = make(map[string]*mcmd.DiffInfo)
	}
	return h.new
}
