package syms

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/blacktop/ipsw/internal/model"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
)

// JSONLConfig configures a streaming JSONL symbol scan.
type JSONLConfig struct {
	IPSW       string
	PemDB      string
	SigsDir    string
	Kernel     bool
	DSC        bool
	FileSystem bool
}

// ipswLine is the single leading record describing the scanned IPSW.
type ipswLine struct {
	Type     string   `json:"type"`
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Build    string   `json:"build"`
	Platform string   `json:"platform"`
	Devices  []string `json:"devices"`
}

// dscLine is emitted once per dyld_shared_cache, carrying its shared_region_start.
// Each dylib image references it by dsc_uuid.
type dscLine struct {
	Type              string `json:"type"`
	UUID              string `json:"uuid"`
	SharedRegionStart uint64 `json:"shared_region_start"`
}

// imageLine describes a single Mach-O image. dsc_uuid is set for dylibs and
// kernel_version for the kernel cache; both are omitted otherwise.
type imageLine struct {
	Type          string `json:"type"`
	UUID          string `json:"uuid"`
	Kind          string `json:"kind"`
	Path          string `json:"path"`
	TextStart     uint64 `json:"text_start"`
	TextEnd       uint64 `json:"text_end"`
	CPU           string `json:"cpu"`
	Arch          string `json:"arch"`
	DSCUUID       string `json:"dsc_uuid,omitempty"`
	KernelVersion string `json:"kernel_version,omitempty"`
}

// symbolLine describes a single symbol within the most recently emitted image.
type symbolLine struct {
	Type      string `json:"type"`
	ImageUUID string `json:"image_uuid"`
	Name      string `json:"name"`
	Start     uint64 `json:"start"`
	End       uint64 `json:"end"`
}

// jsonlEmitter writes scan results as newline-delimited JSON.
type jsonlEmitter struct {
	enc *json.Encoder
}

func newJSONLEmitter(w io.Writer) *jsonlEmitter {
	enc := json.NewEncoder(w)
	// Symbol names and paths are emitted verbatim; HTML escaping would alter
	// names containing <, > or & and break byte-identical name matching.
	enc.SetEscapeHTML(false)
	return &jsonlEmitter{enc: enc}
}

func (e *jsonlEmitter) emit(v any) error {
	return e.enc.Encode(v)
}

// image is a scanVisitor: it emits the image line (or a dsc container line)
// immediately followed by that image's symbol lines.
func (e *jsonlEmitter) image(img *scanImage) error {
	if img.Kind == "dsc" {
		return e.emit(&dscLine{
			Type:              "dsc",
			UUID:              img.DSCUUID,
			SharedRegionStart: img.SharedRegionStart,
		})
	}
	if err := e.emit(&imageLine{
		Type:          "image",
		UUID:          img.Macho.UUID,
		Kind:          img.Kind,
		Path:          img.Macho.GetPath(),
		TextStart:     img.Macho.TextStart,
		TextEnd:       img.Macho.TextEnd,
		CPU:           img.CPU,
		Arch:          img.Arch,
		DSCUUID:       img.DSCUUID,
		KernelVersion: img.KernelVersion,
	}); err != nil {
		return err
	}
	for _, sym := range img.Macho.Symbols {
		if err := e.emit(&symbolLine{
			Type:      "symbol",
			ImageUUID: img.Macho.UUID,
			Name:      sym.GetName(),
			Start:     sym.Start,
			End:       sym.End,
		}); err != nil {
			return err
		}
	}
	return nil
}

// ScanJSONL scans an IPSW and streams its symbols to w as newline-delimited JSON
// (JSONL). It emits one "ipsw" line, then for every image an "image" line
// immediately followed by that image's "symbol" lines (and a one-time "dsc" line
// per shared cache, carrying shared_region_start, which each dylib references via
// dsc_uuid). Symbols are written as they are discovered, so the full symbol set
// is never held in memory.
//
// The emitted addresses use the same normalization as the daemon database, so a
// server backed by this output returns byte-identical results to ipswd.
func ScanJSONL(cfg *JSONLConfig, w io.Writer) error {
	bw := bufio.NewWriter(w)
	// Flush buffered lines on every return path, including early errors, so an
	// aborted scan still writes the records it already produced.
	defer bw.Flush()
	em := newJSONLEmitter(bw)

	sha1, err := utils.Sha1(cfg.IPSW)
	if err != nil {
		return fmt.Errorf("failed to calculate sha1: %w", err)
	}
	inf, err := info.Parse(cfg.IPSW)
	if err != nil {
		return fmt.Errorf("failed to parse IPSW info: %w", err)
	}
	if inf.Plists == nil || inf.Plists.BuildManifest == nil {
		return fmt.Errorf("missing BuildManifest in %s (not a valid IPSW?)", cfg.IPSW)
	}
	if err := em.emit(&ipswLine{
		Type:     "ipsw",
		ID:       sha1,
		Name:     filepath.Base(cfg.IPSW),
		Version:  inf.Plists.BuildManifest.ProductVersion,
		Build:    inf.Plists.BuildManifest.ProductBuildVersion,
		Platform: string(platformFromInfo(inf)),
		Devices:  inf.Plists.BuildManifest.SupportedProductTypes,
	}); err != nil {
		return err
	}

	if err := scanIPSW(&scanConfig{
		IPSW:       cfg.IPSW,
		PemDB:      cfg.PemDB,
		SigsDir:    cfg.SigsDir,
		Kernel:     cfg.Kernel,
		DSC:        cfg.DSC,
		FileSystem: cfg.FileSystem,
	}, em.image); err != nil {
		return err
	}

	return bw.Flush()
}

// platformFromInfo derives the Apple platform for an IPSW from its supported
// product types. The daemon database does not persist this, so the JSONL emitter
// derives it independently.
func platformFromInfo(inf *info.Info) model.Platform {
	for _, dev := range inf.Plists.BuildManifest.SupportedProductTypes {
		switch {
		case strings.HasPrefix(dev, "Mac"):
			return model.PlatformMacOS
		case strings.HasPrefix(dev, "AppleTV"):
			return model.PlatformTvOS
		case strings.HasPrefix(dev, "Watch"):
			return model.PlatformWatchOS
		case strings.HasPrefix(dev, "RealityDevice"):
			return model.PlatformVisionOS
		case strings.HasPrefix(dev, "iPhone"),
			strings.HasPrefix(dev, "iPad"),
			strings.HasPrefix(dev, "iPod"):
			return model.PlatformIOS
		}
	}
	return model.PlatformIOS
}
