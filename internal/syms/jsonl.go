package syms

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"path/filepath"
	"strings"

	"github.com/blacktop/go-macho"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/model"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
)

// JSONLConfig configures a streaming JSONL symbol scan.
type JSONLConfig struct {
	Device string
	// Info is pre-parsed IPSW metadata; when set the IPSW is not parsed again.
	Info       *info.Info
	IPSW       string
	PemDB      string
	SigsDir    string
	Kernel     bool
	DSC        bool
	FileSystem bool
	Facts      bool
}

// ipswLine is the single leading record describing the scanned IPSW.
type ipswLine struct {
	Device   string   `json:"device,omitempty"`
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

type comparisonFactsOccurrence struct {
	Family             string `json:"family"`
	ContainerNamespace string `json:"container_namespace"`
	ContainerID        string `json:"container_id"`
	VolumeLabel        string `json:"volume_label"`
	Path               string `json:"path"`
	UUID               string `json:"uuid"`
	SourceVersion      string `json:"source_version"`
	ComponentPath      string `json:"component_path,omitempty"`
}

const factsSliceSelectionVersion uint32 = 1

type comparisonFactsSliceSelection struct {
	Version              uint32 `json:"version"`
	MachoReference       bool   `json:"macho_reference"`
	EntitlementReference bool   `json:"entitlement_reference"`
}

type comparisonFactsLine struct {
	Type           string                         `json:"type"`
	SchemaVersion  uint32                         `json:"schema_version"`
	Occurrence     comparisonFactsOccurrence      `json:"occurrence"`
	SliceSelection *comparisonFactsSliceSelection `json:"slice_selection,omitempty"`
	Facts          mcmd.ComparisonFacts           `json:"facts"`
}

// jsonlEmitter writes scan results as newline-delimited JSON. Every image
// occurrence (and every DSC container) is written once per scan: an IPSW can
// carry the same Mach-O in several places — a release and a research
// kernelcache embed the same kexts — and consumers key symbols by the image
// occurrence, not by the container it was found in.
type jsonlEmitter struct {
	enc             *json.Encoder
	w               io.Writer
	seen            map[occurrence]struct{}
	factsHash       hash.Hash
	factsCount      uint64
	factsCounts     map[coverageKey]uint64
	componentCounts map[coverageKey]map[string]uint64
}

type coverageKey struct {
	family string
	volume string
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
	return &jsonlEmitter{
		enc: enc, w: w, seen: make(map[occurrence]struct{}), factsHash: sha256.New(),
		factsCounts:     make(map[coverageKey]uint64),
		componentCounts: make(map[coverageKey]map[string]uint64),
	}
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

func (e *jsonlEmitter) facts(img *scanImage, m *macho.File) error {
	if img == nil || img.Macho == nil || m == nil {
		return fmt.Errorf("comparison facts image is incomplete")
	}
	containerImage := img.Kind == "dylib" || img.Kind == "kext"
	facts := mcmd.GenerateComparisonFacts(m, containerImage)
	line := comparisonFactsLine{
		Type:           "comparison_facts",
		SchemaVersion:  mcmd.ComparisonFactsSchemaVersion,
		Occurrence:     comparisonOccurrence(img, m),
		SliceSelection: img.SliceSelection,
		Facts:          facts,
	}
	if img.ComponentPath != "" {
		namespace, err := kernelFactsNamespace(img.ComponentPath)
		if err != nil {
			return err
		}
		line.Occurrence.ContainerNamespace = namespace
		line.Occurrence.ComponentPath = img.ComponentPath
	}
	var encoded bytes.Buffer
	enc := json.NewEncoder(&encoded)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(&line); err != nil {
		return err
	}
	data := encoded.Bytes()
	n, err := e.w.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	if _, err := e.factsHash.Write(data); err != nil {
		return err
	}
	e.factsCount++
	occurrence := line.Occurrence
	e.factsCounts[coverageKey{occurrence.Family, occurrence.VolumeLabel}]++
	if occurrence.ComponentPath != "" {
		key := coverageKey{occurrence.Family, occurrence.VolumeLabel}
		if e.componentCounts[key] == nil {
			e.componentCounts[key] = make(map[string]uint64)
		}
		e.componentCounts[key][occurrence.ComponentPath]++
	}
	return nil
}

func comparisonOccurrence(img *scanImage, m *macho.File) comparisonFactsOccurrence {
	family, namespace, volume, imagePath, containerID := "filesystem_macho", "filesystem", img.VolumeLabel, img.Macho.GetPath(), ""
	switch img.Kind {
	case "dylib":
		family, namespace, volume, containerID = "dsc", "dyld_shared_cache", "dyld_shared_cache", img.DSCUUID
	case "kernel":
		family, namespace, volume, containerID = "kernel", "kernelcache", "kernelcache", img.Macho.UUID
	case "kext":
		family, namespace, volume, containerID = "kext", "kernelcache", "kernelcache", img.KernelUUID
	case "macho":
		if img.KernelPath != "" {
			family, imagePath = "kernel", img.KernelPath
		}
	}
	var sourceVersion string
	if source := m.SourceVersion(); source != nil {
		sourceVersion = source.Version.String()
	}
	return comparisonFactsOccurrence{
		Family:             family,
		ContainerNamespace: namespace,
		ContainerID:        containerID,
		VolumeLabel:        volume,
		Path:               imagePath,
		UUID:               img.Macho.UUID,
		SourceVersion:      sourceVersion,
	}
}

func finishFactsStream(bw *bufio.Writer, emitter *jsonlEmitter, collection *factsCollection) error {
	// Make every prior image record durable before writing the success marker.
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("failed to flush comparison facts records: %w", err)
	}
	completion, err := collection.completion(emitter)
	if err != nil {
		return err
	}
	if err := emitter.emit(&completion); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("failed to flush comparison facts completion: %w", err)
	}
	return nil
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
// In facts mode, a "comparison_facts_collection_start" line follows the "ipsw"
// line. One "comparison_facts" line is emitted per FAT slice, before that file's
// "image"/"symbol" lines when it gets any, including UUID-less Mach-Os and
// deduplicated occurrences (a KEXT shared by release and research kernelcaches,
// or a volume mounted under two labels). Kernelcaches are selected from
// BuildManifest KernelCache components and named from the device-filtered
// metadata, so with a device selection a kernelcache image path can differ from
// the same scan without facts. A final "comparison_facts_complete" line is
// emitted only after every requested source has been scanned successfully.
//
// The emitted addresses use the same normalization as the daemon database, so a
// server backed by this output returns byte-identical results to ipswd. The one
// deliberate divergence is the kernel image class found on the file system
// (scanImage.KernelPath): the daemon keeps those as raw "macho" entries under
// their mount-relative path, the stream emits them as bit-63-cleared "kernel"
// images at their canonical /System/Library/... path.
func ScanJSONL(cfg *JSONLConfig, w io.Writer) (retErr error) {
	bw := bufio.NewWriter(w)
	// Flush buffered lines on every return path, including early errors, so an
	// aborted scan still writes the records it already produced.
	defer func() {
		if err := bw.Flush(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("failed to flush symbols stream: %w", err))
		}
	}()
	em := newJSONLEmitter(bw)

	var source factsSourceIdentity
	var sourceSnapshot *sourceSnapshot
	var sha1 string
	var err error
	if cfg.Facts {
		source, sourceSnapshot, err = readFactsSource(cfg.IPSW)
		if err != nil {
			return fmt.Errorf("failed to calculate source identity: %w", err)
		}
		sha1 = source.LegacySHA1
	} else {
		sha1, err = utils.Sha1(cfg.IPSW)
		if err != nil {
			return fmt.Errorf("failed to calculate sha1: %w", err)
		}
	}
	inf := cfg.Info
	if inf == nil {
		inf, err = info.Parse(cfg.IPSW)
		if err != nil {
			return fmt.Errorf("failed to parse IPSW info: %w", err)
		}
	}
	if inf.Plists == nil || inf.Plists.BuildManifest == nil {
		return fmt.Errorf("missing BuildManifest in %s (not a valid IPSW?)", cfg.IPSW)
	}
	if cfg.DSC || cfg.FileSystem {
		inf, err = inf.SelectDevice(cfg.Device)
	} else {
		inf, err = inf.ForDevice(cfg.Device)
	}
	if err != nil {
		return err
	}
	// A device selection scans only that device's images; list it alone so a
	// consumer matching product types against "devices" sees what the stream
	// covers instead of every product the universal IPSW supports.
	devices := inf.Plists.BuildManifest.SupportedProductTypes
	if cfg.Device != "" {
		devices = []string{inf.ProductType(cfg.Device)}
	}
	if err := em.emit(&ipswLine{
		Device:   cfg.Device,
		Type:     "ipsw",
		ID:       sha1,
		Name:     filepath.Base(cfg.IPSW),
		Version:  inf.Plists.BuildManifest.ProductVersion,
		Build:    inf.Plists.BuildManifest.ProductBuildVersion,
		Platform: string(platformFromInfo(inf)),
		Devices:  devices,
	}); err != nil {
		return err
	}

	var collection *factsCollection
	var facts scanFactsVisitor
	if cfg.Facts {
		collection, err = newFactsCollection(cfg, inf, source)
		if err != nil {
			return err
		}
		if err := em.emit(&collection.start); err != nil {
			return err
		}
		facts = em.facts
	}
	if err := scanIPSW(&scanConfig{
		Info:       inf,
		IPSW:       cfg.IPSW,
		Device:     cfg.Device,
		PemDB:      cfg.PemDB,
		SigsDir:    cfg.SigsDir,
		Kernel:     cfg.Kernel,
		DSC:        cfg.DSC,
		FileSystem: cfg.FileSystem,
		Facts:      facts,
		Collection: collection,
	}, em.image); err != nil {
		return err
	}

	if cfg.Facts {
		if err := sourceSnapshot.validate(cfg.IPSW); err != nil {
			return err
		}
		return finishFactsStream(bw, em, collection)
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
