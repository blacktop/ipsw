package syms

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"slices"
	"strings"
	"unicode"

	"github.com/blacktop/ipsw/internal/commands/mount"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/plist"
)

const symbolsComponentSchemaVersion uint32 = 1
const maxComponentManifestBytes = 128 << 20

// SymbolsComponentSelection requests one BuildManifest KernelCache component.
// Schema 1 currently admits only the kernel family and release/research variants.
type SymbolsComponentSelection struct {
	Name, Path, Variant string
	Families            []string
}

type symbolsComponentDescriptor struct {
	Key     string `json:"key"`
	Name    string `json:"name"`
	Path    string `json:"path"`
	Variant string `json:"variant"`
}

type componentManifestIdentity struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Length int    `json:"length"`
}

type symbolsComponentStartLine struct {
	Type              string                     `json:"type"`
	SchemaVersion     uint32                     `json:"schema_version"`
	Source            factsSourceIdentity        `json:"source"`
	BuildManifest     componentManifestIdentity  `json:"build_manifest"`
	Component         symbolsComponentDescriptor `json:"component"`
	RequestedFamilies []string                   `json:"requested_families"`
	Version           string                     `json:"version"`
	Build             string                     `json:"build"`
	Platform          string                     `json:"platform"`
	Devices           []string                   `json:"devices"`
}

// PreparedSymbolsComponent holds a source-validated, immutable selection. Call
// PrepareComponentJSONL before creating an output file, then call Scan.
type PreparedSymbolsComponent struct {
	cfg      JSONLConfig
	start    symbolsComponentStartLine
	snapshot *sourceSnapshot
}

// ValidateComponentOptions performs no I/O. The component mode has its own
// explicit family selection and cannot inherit legacy device or facts scopes.
func ValidateComponentOptions(cfg *JSONLConfig, selection SymbolsComponentSelection) error {
	if cfg == nil {
		return errors.New("missing component scan configuration")
	}
	if cfg.Device != "" || cfg.Facts || cfg.FactsBoards != nil {
		return errors.New("component symbols cannot be combined with --device, --facts, or --facts-boards")
	}
	if selection.Name != "KernelCache" {
		return fmt.Errorf("symbols component schema 1 supports only KernelCache; component %q is unavailable", selection.Name)
	}
	if len(selection.Path) > 4096 || !fs.ValidPath(selection.Path) || selection.Path == "." ||
		strings.ContainsAny(selection.Path, "\\:") || strings.ContainsFunc(selection.Path, unicode.IsControl) {
		return fmt.Errorf("invalid symbols component path %q", selection.Path)
	}
	if len(selection.Families) != 1 || selection.Families[0] != "kernel" {
		return errors.New("symbols component schema 1 requires only the kernel family; dsc and filesystem are unavailable")
	}
	namespace, err := kernelFactsNamespace(selection.Path)
	if err != nil {
		return err
	}
	if selection.Variant != strings.TrimPrefix(namespace, "kernelcache/") {
		return fmt.Errorf("kernel component variant %q does not match %q", selection.Variant, selection.Path)
	}
	return nil
}

// PrepareComponentJSONL binds the actual source bytes and unique raw manifest.
// Caller-supplied cfg.Info is deliberately ignored in this mode: kernel names
// must derive from the same full source that supplied the exact member.
func PrepareComponentJSONL(cfg *JSONLConfig, selection SymbolsComponentSelection) (*PreparedSymbolsComponent, error) {
	if err := ValidateComponentOptions(cfg, selection); err != nil {
		return nil, err
	}
	source, snapshot, err := readFactsSource(cfg.IPSW)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate component source identity: %w", err)
	}
	zr, err := zip.OpenReader(cfg.IPSW)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	manifestFile, err := mount.ExactArchiveMember(&zr.Reader, "BuildManifest.plist")
	if err != nil {
		return nil, err
	}
	if _, err := mount.ExactArchiveMember(&zr.Reader, selection.Path); err != nil {
		return nil, err
	}
	raw, err := readComponentManifest(manifestFile)
	if err != nil {
		return nil, err
	}
	manifest, err := plist.ParseBuildManifest(raw)
	if err != nil {
		return nil, err
	}
	if err := validateComponentManifest(manifest, selection); err != nil {
		return nil, err
	}
	// Other nested manifests must not replace the unique root manifest while
	// the metadata parser obtains full-source device trees and restore metadata.
	files := make([]*zip.File, 0, len(zr.File))
	for _, file := range zr.File {
		if strings.HasSuffix(file.Name, "BuildManifest.plist") && file != manifestFile {
			continue
		}
		files = append(files, file)
	}
	inf, err := info.ParseZipFiles(files)
	if err != nil {
		return nil, err
	}
	inf.Plists.BuildManifest = manifest
	inf.Plists.SelectedFrom = nil
	if err := snapshot.validate(cfg.IPSW); err != nil {
		return nil, err
	}
	manifestHash := sha256.Sum256(raw)
	manifestIdentity := componentManifestIdentity{"BuildManifest.plist", hex.EncodeToString(manifestHash[:]), len(raw)}
	key := sha256.Sum256([]byte("ipsw-symbols-component/v1\x00" + source.SHA256 + "\x00" +
		manifestIdentity.SHA256 + "\x00" + selection.Name + "\x00" + selection.Path + "\x00" + selection.Variant))
	families := slices.Clone(selection.Families)
	slices.Sort(families)
	prepared := &PreparedSymbolsComponent{
		cfg: *cfg, snapshot: snapshot,
		start: symbolsComponentStartLine{
			Type: "symbols_component_start", SchemaVersion: symbolsComponentSchemaVersion,
			Source: source, BuildManifest: manifestIdentity,
			Component:         symbolsComponentDescriptor{hex.EncodeToString(key[:]), selection.Name, selection.Path, selection.Variant},
			RequestedFamilies: families, Version: manifest.ProductVersion, Build: manifest.ProductBuildVersion,
			Platform: string(platformFromInfo(inf)), Devices: slices.Clone(manifest.SupportedProductTypes),
		},
	}
	prepared.cfg.Info = inf
	return prepared, nil
}

func readComponentManifest(member *zip.File) ([]byte, error) {
	if member.UncompressedSize64 > maxComponentManifestBytes {
		return nil, errors.New("BuildManifest exceeds component scan size limit")
	}
	r, err := member.Open()
	if err != nil {
		return nil, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(r, maxComponentManifestBytes+1))
	if err := errors.Join(readErr, r.Close()); err != nil {
		return nil, err
	}
	if len(raw) > maxComponentManifestBytes || uint64(len(raw)) != member.UncompressedSize64 {
		return nil, errors.New("BuildManifest decoded size does not match its bounded ZIP member")
	}
	return raw, nil
}

func validateComponentManifest(manifest *plist.BuildManifest, selection SymbolsComponentSelection) error {
	for _, identity := range manifest.BuildIdentities {
		component, exists := identity.Manifest[selection.Name]
		member, valid := manifestPath(component)
		if exists && valid && member == selection.Path {
			return nil
		}
	}
	return fmt.Errorf("component %q path %q is absent from the full BuildManifest", selection.Name, selection.Path)
}

// ScanComponentJSONL validates and streams a single component. Callers that
// open a named output file should instead prepare first and call Scan afterward.
func ScanComponentJSONL(cfg *JSONLConfig, selection SymbolsComponentSelection, w io.Writer) error {
	prepared, err := PrepareComponentJSONL(cfg, selection)
	if err != nil {
		return err
	}
	return prepared.Scan(w)
}

func (p *PreparedSymbolsComponent) Scan(w io.Writer) error {
	return p.scan(w, p.scanComponent)
}

func (p *PreparedSymbolsComponent) scan(w io.Writer, scan func(func(string, *scanImage) error) error) (retErr error) {
	if err := p.snapshot.validate(p.cfg.IPSW); err != nil {
		return err
	}
	bw := bufio.NewWriter(w)
	defer func() { retErr = errors.Join(retErr, bw.Flush()) }()
	em := newSymbolsComponentEmitter(bw, p.start.Component, p.start.RequestedFamilies)
	if err := em.control(&p.start); err != nil {
		return err
	}
	if err := scan(em.image); err != nil {
		return err
	}
	if err := p.snapshot.validate(p.cfg.IPSW); err != nil {
		return err
	}
	// Cleanup has returned successfully and every data record must reach the
	// underlying writer before a successful terminal can be attempted.
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("failed to flush component symbols: %w", err)
	}
	if err := em.control(em.completion()); err != nil {
		return err
	}
	return bw.Flush()
}

func (p *PreparedSymbolsComponent) scanComponent(visit func(string, *scanImage) error) error {
	component := p.start.Component
	sigs, err := parseKernelSignatures(p.cfg.SigsDir)
	if err != nil {
		return err
	}
	// The selection narrows extraction, while cfg.Info remains the fixed,
	// complete source for presentation naming.
	one := &factsCollection{start: factsCollectionStartLine{Selection: factsManifestSelection{
		Identities: []factsManifestIdentity{{Components: []factsManifestComponent{{Name: "KernelCache", Path: component.Path}}}},
	}}}
	return scanKernels(p.cfg.IPSW, sigs, "", p.cfg.Info, one, func(img *scanImage) error {
		return visit("kernel", img)
	}, nil)
}

type componentRecordCounts struct {
	Records uint64 `json:"records"`
	DSCs    uint64 `json:"dscs"`
	Images  uint64 `json:"images"`
	Symbols uint64 `json:"symbols"`
}

type symbolsComponentOperation struct {
	ComponentKey string `json:"component_key"`
	Family       string `json:"family"`
	Status       string `json:"status"`
	componentRecordCounts
}

type symbolsComponentCompleteLine struct {
	Type                          string `json:"type"`
	SchemaVersion                 uint32 `json:"schema_version"`
	ComponentKey                  string `json:"component_key"`
	Status                        string `json:"status"`
	RequiresSuccessfulProcessExit bool   `json:"requires_successful_process_exit"`
	RecordsSHA256                 string `json:"records_sha256"`
	componentRecordCounts
	Operations []symbolsComponentOperation `json:"operations"`
}

type componentOccurrence struct {
	ComponentKey string `json:"component_key"`
	Family       string `json:"family"`
	UUID         string `json:"uuid"`
	Kind         string `json:"kind"`
	Path         string `json:"path"`
	TextStart    uint64 `json:"text_start"`
	TextEnd      uint64 `json:"text_end"`
	CPU          string `json:"cpu"`
	Arch         string `json:"arch"`
	DSCUUID      string `json:"dsc_uuid"`
	KernelUUID   string `json:"kernel_uuid"`
}

type symbolsComponentEmitter struct {
	w          io.Writer
	component  symbolsComponentDescriptor
	seen       map[componentOccurrence]struct{}
	hash       hash.Hash
	counts     componentRecordCounts
	operations []symbolsComponentOperation
}

func newSymbolsComponentEmitter(w io.Writer, component symbolsComponentDescriptor, families []string) *symbolsComponentEmitter {
	e := &symbolsComponentEmitter{w: w, component: component, seen: make(map[componentOccurrence]struct{}), hash: sha256.New()}
	for _, family := range families {
		e.operations = append(e.operations, symbolsComponentOperation{ComponentKey: component.Key, Family: family, Status: "successful"})
	}
	return e
}

func componentRecordBytes(value any) ([]byte, error) {
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func (e *symbolsComponentEmitter) control(value any) error {
	data, err := componentRecordBytes(value)
	if err != nil {
		return err
	}
	n, err := e.w.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return err
}

func (e *symbolsComponentEmitter) data(family, kind string, value any) error {
	idx := slices.IndexFunc(e.operations, func(op symbolsComponentOperation) bool { return op.Family == family })
	if idx < 0 {
		return fmt.Errorf("scanner emitted unrequested family %q", family)
	}
	data, err := componentRecordBytes(value)
	if err != nil {
		return err
	}
	n, err := e.w.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	_, _ = e.hash.Write(data)
	for _, counts := range []*componentRecordCounts{&e.counts, &e.operations[idx].componentRecordCounts} {
		counts.Records++
		switch kind {
		case "dsc":
			counts.DSCs++
		case "image":
			counts.Images++
		case "symbol":
			counts.Symbols++
		}
	}
	return nil
}

func (e *symbolsComponentEmitter) image(family string, img *scanImage) error {
	if img == nil || img.ComponentPath != e.component.Path || (img.Kind != "dsc" && img.Macho == nil) {
		return errors.New("component scanner emitted missing or mismatched source provenance")
	}
	switch family {
	case "kernel":
		if (img.Kind != "kernel" && img.Kind != "kext") || (img.Kind == "kext" && img.KernelUUID == "") {
			return errors.New("kernel scanner emitted an invalid image or parent identity")
		}
	case "dsc":
		if (img.Kind != "dsc" && img.Kind != "dylib") || img.DSCUUID == "" {
			return errors.New("DSC scanner emitted an invalid image or parent identity")
		}
	case "filesystem":
		if img.Kind != "macho" {
			return errors.New("filesystem scanner emitted an invalid image kind")
		}
	default:
		return fmt.Errorf("scanner emitted unrequested family %q", family)
	}
	key := componentOccurrence{ComponentKey: e.component.Key, Family: family, KernelUUID: img.KernelUUID}
	var line *imageLine
	mask := ^uint64(0)
	if img.Kind == "dsc" {
		key.UUID, key.Kind = img.DSCUUID, "dsc"
	} else {
		line, mask = normalizedImageLine(img)
		key.UUID, key.Kind, key.Path = line.UUID, line.Kind, line.Path
		key.TextStart, key.TextEnd = line.TextStart, line.TextEnd
		key.CPU, key.Arch, key.DSCUUID = line.CPU, line.Arch, line.DSCUUID
	}
	if _, exists := e.seen[key]; exists {
		return nil
	}
	encodedKey, err := componentRecordBytes(key)
	if err != nil {
		return err
	}
	idHash := sha256.Sum256(append([]byte("ipsw-symbols-occurrence/v1\x00"), encodedKey...))
	id := hex.EncodeToString(idHash[:])
	e.seen[key] = struct{}{}
	if img.Kind == "dsc" {
		return e.data(family, "dsc", struct {
			dscLine
			ComponentKey string `json:"component_key"`
			Family       string `json:"family"`
			OccurrenceID string `json:"occurrence_id"`
		}{dscLine{"dsc", img.DSCUUID, img.SharedRegionStart, img.ComponentPath}, e.component.Key, family, id})
	}
	if err := e.data(family, "image", struct {
		*imageLine
		ComponentKey  string `json:"component_key"`
		ComponentPath string `json:"component_path"`
		Family        string `json:"family"`
		OccurrenceID  string `json:"occurrence_id"`
		KernelUUID    string `json:"kernel_uuid,omitempty"`
	}{line, e.component.Key, img.ComponentPath, family, id, img.KernelUUID}); err != nil {
		return err
	}
	for _, symbol := range img.Macho.Symbols {
		if err := e.data(family, "symbol", struct {
			symbolLine
			OccurrenceID string `json:"occurrence_id"`
		}{symbolLine{"symbol", line.UUID, symbol.GetName(), symbol.Start & mask, symbol.End & mask}, id}); err != nil {
			return err
		}
	}
	return nil
}

func (e *symbolsComponentEmitter) completion() *symbolsComponentCompleteLine {
	return &symbolsComponentCompleteLine{
		Type: "symbols_component_complete", SchemaVersion: symbolsComponentSchemaVersion,
		ComponentKey: e.component.Key, Status: "successful", RequiresSuccessfulProcessExit: true,
		RecordsSHA256: hex.EncodeToString(e.hash.Sum(nil)), componentRecordCounts: e.counts,
		Operations: slices.Clone(e.operations),
	}
}
