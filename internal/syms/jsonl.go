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

// jsonlEmitter writes scan results as newline-delimited JSON. Every image
// occurrence (and every DSC container) is written once per scan: an IPSW can
// carry the same Mach-O in several places — a release and a research
// kernelcache embed the same kexts — and consumers key symbols by the image
// occurrence, not by the container it was found in.
type jsonlEmitter struct {
	enc  *json.Encoder
	seen map[occurrence]struct{}
}

// occurrence identifies an emitted image the way a symbol consumer does: by
// UUID, kind, path, text range, architecture and parent DSC. A DSC container
// is keyed by its UUID and kind "dsc".
type occurrence struct {
	uuid, kind, path   string
	textStart, textEnd uint64
	cpu, arch, dscUUID string
}

func newJSONLEmitter(w io.Writer) *jsonlEmitter {
	enc := json.NewEncoder(w)
	// Symbol names and paths are emitted verbatim; HTML escaping would alter
	// names containing <, > or & and break byte-identical name matching.
	enc.SetEscapeHTML(false)
	return &jsonlEmitter{enc: enc, seen: make(map[occurrence]struct{})}
}

// first records key and reports whether this is its first appearance.
func (e *jsonlEmitter) first(key occurrence) bool {
	if _, ok := e.seen[key]; ok {
		return false
	}
	e.seen[key] = struct{}{}
	return true
}

func (e *jsonlEmitter) emit(v any) error {
	return e.enc.Encode(v)
}

// image is a scanVisitor: it emits the image line (or a dsc container line)
// immediately followed by that image's symbol lines.
func (e *jsonlEmitter) image(img *scanImage) error {
	if img.Kind == "dsc" {
		if !e.first(occurrence{uuid: img.DSCUUID, kind: "dsc"}) {
			return nil
		}
		return e.emit(&dscLine{
			Type:              "dsc",
			UUID:              img.DSCUUID,
			SharedRegionStart: img.SharedRegionStart,
		})
	}
	kind, imgPath, mask := img.Kind, img.Macho.GetPath(), ^uint64(0)
	if img.KernelPath != "" {
		// The daemon model keeps file-system kernels as raw "macho" entries;
		// the stream presents them as the kernel images they are, at their
		// canonical path and bit-63-cleared like scanKernels stores kernelcache
		// kernels and KEXTs, so one address convention covers every kind=kernel.
		kind, imgPath, mask = "kernel", img.KernelPath, highestBitMask
	}
	line := &imageLine{
		Type:          "image",
		UUID:          img.Macho.UUID,
		Kind:          kind,
		Path:          imgPath,
		TextStart:     img.Macho.TextStart & mask,
		TextEnd:       img.Macho.TextEnd & mask,
		CPU:           img.CPU,
		Arch:          img.Arch,
		DSCUUID:       img.DSCUUID,
		KernelVersion: img.KernelVersion,
	}
	if !e.first(occurrence{
		uuid: line.UUID, kind: line.Kind, path: line.Path,
		textStart: line.TextStart, textEnd: line.TextEnd,
		cpu: line.CPU, arch: line.Arch, dscUUID: line.DSCUUID,
	}) {
		return nil
	}
	if err := e.emit(line); err != nil {
		return err
	}
	for _, sym := range img.Macho.Symbols {
		if err := e.emit(&symbolLine{
			Type:      "symbol",
			ImageUUID: img.Macho.UUID,
			Name:      sym.GetName(),
			Start:     sym.Start & mask,
			End:       sym.End & mask,
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
// is never held in memory. An image occurrence (UUID, kind, path, text range,
// arch, DSC) is written once per scan even when the IPSW carries it in several
// containers, such as a kext shared by a release and a research kernelcache.
//
// The emitted addresses use the same normalization as the daemon database, so a
// server backed by this output returns byte-identical results to ipswd. The one
// deliberate divergence is the kernel image class found on the file system
// (scanImage.KernelPath): the daemon keeps those as raw "macho" entries under
// their mount-relative path, the stream emits them as bit-63-cleared "kernel"
// images at their canonical /System/Library/... path.
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
