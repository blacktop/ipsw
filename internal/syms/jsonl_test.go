package syms

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	gomacho "github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/model"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/plist"
)

// rawLines splits a JSONL buffer into its non-blank lines.
func rawLines(t *testing.T, b []byte) [][]byte {
	t.Helper()
	var lines [][]byte
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		lines = append(lines, bytes.Clone(sc.Bytes()))
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan error: %v", err)
	}
	return lines
}

func TestFactsEmitterPreservesDistinctVolumeOccurrences(t *testing.T) {
	for typ, want := range map[string]string{
		"fs": "filesystem", "sys": "SystemOS", "app": "AppOS", "exc": "ExclaveOS",
	} {
		if got := factsVolumeLabel(typ); got != want {
			t.Fatalf("facts volume label %q = %q, want %q", typ, got, want)
		}
	}

	var buf bytes.Buffer
	em := newJSONLEmitter(&buf)
	source := &gomacho.File{FileTOC: gomacho.FileTOC{FileHeader: types.FileHeader{
		CPU: types.CPUArm64, SubCPU: types.CPUSubtypeArm64E,
	}}}
	image := func(volume string) *scanImage {
		return &scanImage{
			Kind:        "macho",
			VolumeLabel: volume,
			Macho: &model.Macho{
				UUID: "SAME-UUID",
				Path: model.Path{Path: "/usr/lib/same.dylib"},
			},
		}
	}

	for _, volume := range []string{"SystemOS", "AppOS"} {
		if err := em.facts(image(volume), source); err != nil {
			t.Fatalf("emit %s facts: %v", volume, err)
		}
	}

	lines := rawLines(t, buf.Bytes())
	if len(lines) != 2 {
		t.Fatalf("facts lines = %d, want 2: %s", len(lines), buf.String())
	}
	var first, second comparisonFactsLine
	if err := json.Unmarshal(lines[0], &first); err != nil {
		t.Fatalf("decode first facts record: %v", err)
	}
	if err := json.Unmarshal(lines[1], &second); err != nil {
		t.Fatalf("decode second facts record: %v", err)
	}
	if first.Occurrence.Path != second.Occurrence.Path || first.Occurrence.UUID != second.Occurrence.UUID {
		t.Fatalf("test inputs did not preserve same image identity: first=%+v second=%+v", first.Occurrence, second.Occurrence)
	}
	if first.Occurrence.VolumeLabel != "SystemOS" || second.Occurrence.VolumeLabel != "AppOS" {
		t.Fatalf("volume occurrences collapsed or relabeled: first=%+v second=%+v", first.Occurrence, second.Occurrence)
	}
	if first.Facts.CPU.Type != uint32(types.CPUArm64) || first.Facts.CPU.Subtype != uint32(types.CPUSubtypeArm64E) {
		t.Fatalf("numeric CPU identity missing: %+v", first.Facts.CPU)
	}
}

type failSecondWrite struct {
	buf   bytes.Buffer
	calls int
}

func (w *failSecondWrite) Write(data []byte) (int, error) {
	w.calls++
	if w.calls == 2 {
		return 0, errors.New("synthetic writer failure")
	}
	return w.buf.Write(data)
}

func TestFactsCompletionRequiresSuccessfulWriter(t *testing.T) {
	w := &failSecondWrite{}
	bw := bufio.NewWriterSize(w, 4096)
	em := newJSONLEmitter(bw)
	em.factsCount = 1
	em.factsCounts[coverageKey{"kernel", "kernelcache"}] = 1
	if err := em.emit(map[string]string{"type": "comparison_facts"}); err != nil {
		t.Fatalf("emit facts record: %v", err)
	}

	err := finishFactsStream(bw, em, &factsCollection{coverage: []factsCoverage{{
		Family: "kernel", Volume: "kernelcache", Status: "successful",
	}}})
	if err == nil || !strings.Contains(err.Error(), "synthetic writer failure") {
		t.Fatalf("finish error = %v, want synthetic writer failure", err)
	}
	if strings.Contains(w.buf.String(), "comparison_facts_complete") {
		t.Fatalf("failed stream contains successful completion: %s", w.buf.String())
	}
	if !strings.Contains(w.buf.String(), `"type":"comparison_facts"`) {
		t.Fatalf("pre-failure facts record was not flushed: %s", w.buf.String())
	}
}

func TestFactsCompletionRecordsSuccessfulStream(t *testing.T) {
	var out bytes.Buffer
	bw := bufio.NewWriter(&out)
	em := newJSONLEmitter(bw)
	em.factsCount = 3
	em.factsCounts[coverageKey{"kernel", "kernelcache"}] = 3
	if err := finishFactsStream(bw, em, &factsCollection{coverage: []factsCoverage{{
		Family: "kernel", Volume: "kernelcache", Status: "successful",
	}}}); err != nil {
		t.Fatalf("finish facts stream: %v", err)
	}
	lines := rawLines(t, out.Bytes())
	if len(lines) != 1 {
		t.Fatalf("completion lines = %d, want 1", len(lines))
	}
	var completion comparisonFactsCompleteLine
	if err := json.Unmarshal(lines[0], &completion); err != nil {
		t.Fatalf("decode completion: %v", err)
	}
	if completion.Type != "comparison_facts_complete" || completion.Records != 3 || !completion.RequiresSuccessfulProcessExit {
		t.Fatalf("completion = %+v", completion)
	}
}

func TestFactsSourceIdentityUsesBytesAndDetectsChanges(t *testing.T) {
	path := t.TempDir() + "/source.ipsw"
	data := []byte("synthetic source bytes")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	source, snapshot, err := readFactsSource(path)
	if err != nil {
		t.Fatalf("read source identity: %v", err)
	}
	wantSHA1, wantSHA256 := sha1.Sum(data), sha256.Sum256(data)
	if source.LegacySHA1 != fmt.Sprintf("%x", wantSHA1) || source.SHA256 != fmt.Sprintf("%x", wantSHA256) || source.Length != int64(len(data)) {
		t.Fatalf("source identity = %+v", source)
	}
	if err := snapshot.validate(path); err != nil {
		t.Fatalf("unchanged source rejected: %v", err)
	}
	if err := os.WriteFile(path, append(data, '!'), 0o600); err != nil {
		t.Fatalf("change source: %v", err)
	}
	if err := snapshot.validate(path); err == nil {
		t.Fatal("changed source passed consistency validation")
	}
}

func TestFactsCollectionBindsAllSelectedIdentitiesDeterministically(t *testing.T) {
	identity := func(board, kernel string) plist.BuildIdentity {
		return plist.BuildIdentity{
			ApProductType: "iPhone18,1",
			Info:          plist.IdentityInfo{DeviceClass: board, Variant: "Customer Erase Install (IPSW)"},
			Manifest: map[string]plist.IdentityManifest{
				"KernelCache":       {Info: map[string]any{"Path": kernel}},
				"OS":                {Info: map[string]any{"Path": "filesystem.dmg"}},
				"Cryptex1,SystemOS": {Info: map[string]any{"Path": "system.dmg"}},
			},
		}
	}
	newInfo := func(identities []plist.BuildIdentity) *info.Info {
		return &info.Info{Plists: &plist.Plists{BuildManifest: &plist.BuildManifest{
			SupportedProductTypes: []string{"iPhone18,1"}, BuildIdentities: identities,
		}}}
	}
	cfg := &JSONLConfig{Device: "iPhone18,1", Kernel: true, FileSystem: true}
	source := factsSourceIdentity{LegacySHA1: "sha1", SHA256: "sha256", Length: 42}
	first, err := newFactsCollection(cfg, newInfo([]plist.BuildIdentity{
		identity("d24ap", "kernelcache.research.d24"), identity("d23ap", "kernelcache.release.d23"),
	}), source)
	if err != nil {
		t.Fatalf("first collection: %v", err)
	}
	second, err := newFactsCollection(cfg, newInfo([]plist.BuildIdentity{
		identity("d23ap", "kernelcache.release.d23"), identity("d24ap", "kernelcache.research.d24"),
	}), source)
	if err != nil {
		t.Fatalf("second collection: %v", err)
	}
	if first.start.CollectionID != second.start.CollectionID {
		t.Fatalf("collection ID depends on identity order: %s != %s", first.start.CollectionID, second.start.CollectionID)
	}
	if !slices.Equal(first.start.Selection.Boards, []string{"d23ap", "d24ap"}) || len(first.start.Selection.Identities) != 2 {
		t.Fatalf("selection lost identities: %+v", first.start.Selection)
	}
	wantKernels := []string{"kernelcache.release.d23", "kernelcache.research.d24"}
	if got := componentPaths(first.start.Selection, "KernelCache"); !slices.Equal(got, wantKernels) {
		t.Fatalf("kernel components = %v, want %v", got, wantKernels)
	}
}

func TestFactsCollectionRejectsEmptyKernelSelection(t *testing.T) {
	const selector = "iPhone18,1"
	inf := testVolumeInfo(map[string]string{"OS": "filesystem.dmg"})
	collection, err := newFactsCollection(&JSONLConfig{Device: selector, Kernel: true}, inf, factsSourceIdentity{})
	if err == nil || !strings.Contains(err.Error(), selector) || !strings.Contains(err.Error(), "KernelCache") {
		t.Fatalf("expected empty KernelCache selection error naming %q, got %v", selector, err)
	}
	if collection != nil {
		t.Fatal("empty kernel selection returned a collection")
	}
}

func TestFactsCollectionVersionsFilesystemContract(t *testing.T) {
	inf := testVolumeInfo(map[string]string{"OS": "filesystem.dmg", "KernelCache": "kernelcache.release.test"})
	source := factsSourceIdentity{LegacySHA1: "sha1", SHA256: "sha256", Length: 42}
	kernelOnly, err := newFactsCollection(&JSONLConfig{Kernel: true}, inf, source)
	if err != nil {
		t.Fatal(err)
	}
	filesystem, err := newFactsCollection(&JSONLConfig{FileSystem: true}, inf, source)
	if err != nil {
		t.Fatal(err)
	}
	if kernelOnly.start.CollectionSchemaVersion != factsCollectionSchemaVersionV3 {
		t.Fatalf("kernel-only collection version = %d, want v3", kernelOnly.start.CollectionSchemaVersion)
	}
	if filesystem.start.CollectionSchemaVersion != factsCollectionSchemaVersionV2 {
		t.Fatalf("filesystem collection version = %d, want v2", filesystem.start.CollectionSchemaVersion)
	}
	v1ID, err := factsCollectionID(factsCollectionSchemaVersionV1, source, filesystem.start.Selection, filesystem.start.Requested)
	if err != nil {
		t.Fatal(err)
	}
	if v1ID == filesystem.start.CollectionID {
		t.Fatal("collection ID is not bound to the collection schema version")
	}
	for _, family := range []string{"standalone_entitlements", "symbol_table", "cstring_comparison", "function_start_comparison"} {
		row := findCoverage(t, filesystem.coverage, family, "all")
		if row.Status != "unavailable" {
			t.Fatalf("%s coverage = %+v, want explicitly unavailable", family, row)
		}
	}
	filesystem.coverage = []factsCoverage{{Family: "filesystem_macho", Volume: "filesystem", Status: "successful"}}
	emitter := newJSONLEmitter(&bytes.Buffer{})
	completion, err := filesystem.completion(emitter)
	if err != nil {
		t.Fatal(err)
	}
	if completion.CollectionSchemaVersion != factsCollectionSchemaVersionV2 || completion.CollectionID != filesystem.start.CollectionID {
		t.Fatalf("filesystem completion = %+v", completion)
	}
}

func TestFactsCoverageDistinguishesAbsentAliasAndUnselected(t *testing.T) {
	selection := factsManifestSelection{Identities: []factsManifestIdentity{{Components: []factsManifestComponent{
		{Name: "OS", Path: "shared.dmg"},
	}}}}
	selected := initialFactsCoverage(&JSONLConfig{FileSystem: true}, selection)
	if row := findCoverage(t, selected, "filesystem_macho", "filesystem"); row.Status != "unavailable" {
		t.Fatalf("selected filesystem = %+v", row)
	}
	if row := findCoverage(t, selected, "filesystem_macho", "SystemOS"); row.Status != "unavailable" || row.AliasOf != "filesystem" {
		t.Fatalf("SystemOS alias = %+v", row)
	}
	if row := findCoverage(t, selected, "filesystem_macho", "AppOS"); row.Status != "absent" {
		t.Fatalf("absent AppOS = %+v", row)
	}
	unselected := initialFactsCoverage(&JSONLConfig{}, selection)
	if row := findCoverage(t, unselected, "filesystem_macho", "AppOS"); row.Status != "not-selected" {
		t.Fatalf("unselected AppOS = %+v", row)
	}
}

func TestFactsCompletionReconcilesExactFramedRecords(t *testing.T) {
	var body bytes.Buffer
	em := newJSONLEmitter(&body)
	source := &gomacho.File{FileTOC: gomacho.FileTOC{FileHeader: types.FileHeader{CPU: types.CPUArm64}}}
	images := []*scanImage{
		{Kind: "kernel", Macho: &model.Macho{UUID: "KERNEL"}},
		{Kind: "kext", KernelUUID: "KERNEL", Macho: &model.Macho{UUID: "KEXT"}},
		{Kind: "dylib", DSCUUID: "DSC", Macho: &model.Macho{UUID: "DYLIB"}},
	}
	for _, image := range images {
		if err := em.facts(image, source); err != nil {
			t.Fatalf("emit %s: %v", image.Kind, err)
		}
	}
	collection := &factsCollection{start: factsCollectionStartLine{CollectionID: "bound"}, coverage: []factsCoverage{
		{Family: "kernel", Volume: "kernelcache", Status: "successful"},
		{Family: "kext", Volume: "kernelcache", Status: "successful"},
		{Family: "dsc", Volume: "SystemOS", RecordVolume: "dyld_shared_cache", Status: "successful"},
	}}
	completion, err := collection.completion(em)
	if err != nil {
		t.Fatalf("complete collection: %v", err)
	}
	wantDigest := sha256.Sum256(body.Bytes())
	if completion.Records != 3 || completion.RecordsSHA256 != fmt.Sprintf("%x", wantDigest) {
		t.Fatalf("completion = %+v", completion)
	}
	var covered uint64
	for _, row := range completion.Coverage {
		covered += row.Records
	}
	if covered != completion.Records {
		t.Fatalf("coverage records = %d, total = %d", covered, completion.Records)
	}
	collection.coverage[0].Status = "unavailable"
	collection.coverage[0].Reason = "selected collection did not finish"
	if _, err := collection.completion(em); err == nil {
		t.Fatal("incomplete selected coverage produced a completion")
	}
}

func TestFactsKernelComponentsRemainIndependent(t *testing.T) {
	var body bytes.Buffer
	emitter := newJSONLEmitter(&body)
	source := &gomacho.File{FileTOC: gomacho.FileTOC{FileHeader: types.FileHeader{CPU: types.CPUArm64}}}
	paths := []string{"kernelcache.release.iphone17", "kernelcache.research.iphone17"}
	collection := &factsCollection{start: factsCollectionStartLine{CollectionSchemaVersion: 3},
		coverage: []factsCoverage{
			{Family: "kernel", Volume: "kernelcache", Status: "successful", ComponentPaths: paths},
			{Family: "kext", Volume: "kernelcache", Status: "successful", ComponentPaths: paths},
		}}
	for _, component := range paths {
		for _, kind := range []string{"kernel", "kext"} {
			image := &scanImage{Kind: kind, ComponentPath: component, KernelUUID: "KERNEL",
				Macho: &model.Macho{UUID: kind, Path: model.Path{Path: "same-image"}}}
			if err := emitter.facts(image, source); err != nil {
				t.Fatal(err)
			}
		}
	}
	lines := rawLines(t, body.Bytes())
	if len(lines) != 4 {
		t.Fatalf("shared names/UUIDs lost occurrences: %d", len(lines))
	}
	var release, research comparisonFactsLine
	if err := json.Unmarshal(lines[1], &release); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(lines[3], &research); err != nil {
		t.Fatal(err)
	}
	if release.Occurrence.ContainerNamespace != "kernelcache/release" || research.Occurrence.ContainerNamespace != "kernelcache/research" ||
		release.Occurrence.ComponentPath != paths[0] || research.Occurrence.ComponentPath != paths[1] ||
		!reflect.DeepEqual(release.Facts, research.Facts) {
		t.Fatal("component provenance was lost or leaked into semantic facts")
	}
	footer, err := collection.completion(emitter)
	if err != nil || footer.Records != 4 || len(footer.Coverage[0].ComponentRecords) != 2 {
		t.Fatalf("component completion: %+v, %v", footer, err)
	}
	delete(emitter.componentCounts[coverageKey{"kernel", "kernelcache"}], paths[1])
	if _, err := collection.completion(emitter); err == nil {
		t.Fatal("missing research container accepted")
	}
	if _, err := kernelFactsNamespace("kernelcache.unknown.iphone17"); err == nil {
		t.Fatal("unknown variant silently classified")
	}
}

func TestFactsKernelExtractionRetainsArchivePaths(t *testing.T) {
	paths := []string{"kernelcache.release.iphone17", "kernelcache.research.iphone17"}
	inf := testVolumeInfo(map[string]string{"KernelCache": paths[0]}, map[string]string{"KernelCache": paths[1]})
	collection, err := newFactsCollection(&JSONLConfig{Kernel: true}, inf, factsSourceIdentity{})
	if err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	for _, component := range paths {
		payload, err := img4.CreatePayload(&img4.CreatePayloadConfig{
			Type: img4.IM4P_KERNELCACHE, Version: "test", Data: []byte(component), Compression: "lzss",
		})
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := payload.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		entry, err := writer.Create(component)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(encoded); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "test.ipsw")
	if err := os.WriteFile(source, archive.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	extracted, err := extractScanKernels(source, "", t.TempDir(), inf, collection)
	if err != nil || len(extracted) != 2 {
		t.Fatalf("extract exact kernel components: %v, %v", extracted, err)
	}
	for file, component := range extracted {
		data, err := os.ReadFile(file)
		if err != nil || string(data) != component {
			t.Fatalf("extracted payload/source mismatch: %q, %q, %v", component, data, err)
		}
	}
}

func findCoverage(t *testing.T, rows []factsCoverage, family, volume string) factsCoverage {
	t.Helper()
	for _, row := range rows {
		if row.Family == family && row.Volume == volume {
			return row
		}
	}
	t.Fatalf("missing coverage %s/%s", family, volume)
	return factsCoverage{}
}

func TestLegacyJSONLHeaderBytesRemainUnchanged(t *testing.T) {
	var out bytes.Buffer
	em := newJSONLEmitter(&out)
	if err := em.emit(&ipswLine{Type: "ipsw", ID: "legacy-sha1", Name: "source.ipsw", Version: "26.6", Build: "23G71", Platform: "ios", Devices: []string{"iPhone18,1"}}); err != nil {
		t.Fatalf("emit header: %v", err)
	}
	want := "{\"type\":\"ipsw\",\"id\":\"legacy-sha1\",\"name\":\"source.ipsw\",\"version\":\"26.6\",\"build\":\"23G71\",\"platform\":\"ios\",\"devices\":[\"iPhone18,1\"]}\n"
	if out.String() != want {
		t.Fatalf("legacy header changed:\n got %q\nwant %q", out.String(), want)
	}
}

// decodeLines splits a JSONL buffer into a slice of generic maps, one per line.
func decodeLines(t *testing.T, b []byte) []map[string]any {
	t.Helper()
	var lines []map[string]any
	for _, raw := range rawLines(t, b) {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("invalid JSON line %q: %v", string(raw), err)
		}
		lines = append(lines, m)
	}
	return lines
}

// TestEmitterLineTypesAndFields drives the JSONL emitter with synthetic images
// and asserts the line types, field names, and lossless symbol round-trip
// without needing a real IPSW.
func TestEmitterLineTypesAndFields(t *testing.T) {
	var buf bytes.Buffer
	em := newJSONLEmitter(&buf)

	if err := em.emit(&ipswLine{
		Type:     "ipsw",
		ID:       "abc123",
		Name:     "iPhone18,1_26.5_23F75_Restore.ipsw",
		Version:  "26.5",
		Build:    "23F75",
		Platform: string(model.PlatformIOS),
		Devices:  []string{"iPhone18,1"},
	}); err != nil {
		t.Fatalf("emit ipsw: %v", err)
	}

	// DSC container + one dylib carrying a single symbol.
	if err := em.image(&scanImage{
		Kind:              "dsc",
		DSCUUID:           "DSC-UUID",
		SharedRegionStart: 0x180000000,
	}); err != nil {
		t.Fatalf("emit dsc: %v", err)
	}
	const (
		symStart uint64 = 0x1DC2A1000
		symEnd   uint64 = 0x1DC2A1100
		probe    uint64 = 0x1DC2A1050 // start <= probe < end
	)
	if err := em.image(&scanImage{
		Kind:    "dylib",
		CPU:     "arm64e",
		Arch:    "arm64e",
		DSCUUID: "DSC-UUID",
		Macho: &model.Macho{
			UUID:      "DYLIB-UUID",
			Path:      model.Path{Path: "/usr/lib/libobjc.A.dylib"},
			TextStart: 0x1DC2A0000,
			TextEnd:   0x1DC2B0000,
			Symbols: []*model.Symbol{
				{Name: model.Name{Name: "_objc_msgSend"}, Start: symStart, End: symEnd},
			},
		},
	}); err != nil {
		t.Fatalf("emit dylib: %v", err)
	}

	// Kernel image carrying kernel_version.
	if err := em.image(&scanImage{
		Kind:          "kernel",
		CPU:           "arm64e",
		Arch:          "arm64e",
		KernelVersion: "Darwin Kernel Version 26.5",
		Macho: &model.Macho{
			UUID:      "KERNEL-UUID",
			Path:      model.Path{Path: "kernelcache"},
			TextStart: 0xFFFFFE0007004000,
			TextEnd:   0xFFFFFE0007804000,
		},
	}); err != nil {
		t.Fatalf("emit kernel: %v", err)
	}

	lines := decodeLines(t, buf.Bytes())
	// Line order: ipsw, dsc, image(dylib), symbol, image(kernel).
	wantTypes := []string{"ipsw", "dsc", "image", "symbol", "image"}
	if len(lines) != len(wantTypes) {
		t.Fatalf("expected %d lines, got %d: %v", len(wantTypes), len(lines), lines)
	}
	for i, want := range wantTypes {
		if lines[i]["type"] != want {
			t.Fatalf("line[%d] type = %v, want %s", i, lines[i]["type"], want)
		}
	}

	// The dsc line must carry shared_region_start.
	dsc := lines[1]
	if dsc["type"] != "dsc" {
		t.Fatalf("line[1] type = %v, want dsc", dsc["type"])
	}
	if _, ok := dsc["shared_region_start"]; !ok {
		t.Fatalf("dsc line missing shared_region_start: %v", dsc)
	}

	// The dylib image line: kind=dylib, dsc_uuid set, text range present.
	img := lines[2]
	if img["type"] != "image" || img["kind"] != "dylib" {
		t.Fatalf("line[2] = %v, want image/dylib", img)
	}
	for _, f := range []string{"uuid", "kind", "path", "text_start", "text_end", "cpu", "arch", "dsc_uuid"} {
		if _, ok := img[f]; !ok {
			t.Fatalf("image line missing field %q: %v", f, img)
		}
	}
	if img["dsc_uuid"] != "DSC-UUID" {
		t.Fatalf("image dsc_uuid = %v, want DSC-UUID", img["dsc_uuid"])
	}

	// The symbol line: image_uuid + numeric start/end matching the input.
	sym := lines[3]
	if sym["type"] != "symbol" {
		t.Fatalf("line[3] type = %v, want symbol", sym["type"])
	}
	for _, f := range []string{"image_uuid", "name", "start", "end"} {
		if _, ok := sym[f]; !ok {
			t.Fatalf("symbol line missing field %q: %v", f, sym)
		}
	}
	if sym["image_uuid"] != "DYLIB-UUID" {
		t.Fatalf("symbol image_uuid = %v, want DYLIB-UUID", sym["image_uuid"])
	}
	gotStart, ok := sym["start"].(float64)
	if !ok {
		t.Fatalf("symbol start is not a JSON number: %T", sym["start"])
	}
	gotEnd, ok := sym["end"].(float64)
	if !ok {
		t.Fatalf("symbol end is not a JSON number: %T", sym["end"])
	}
	if uint64(gotStart) != symStart || uint64(gotEnd) != symEnd {
		t.Fatalf("symbol [start,end) = [%d,%d), want [%d,%d)", uint64(gotStart), uint64(gotEnd), symStart, symEnd)
	}
	// Lossless round-trip: an address resolvable via start <= addr < end is
	// derivable from the emitted JSONL.
	if !(probe >= uint64(gotStart) && probe < uint64(gotEnd)) {
		t.Fatalf("probe %#x not within emitted symbol range [%#x,%#x)", probe, uint64(gotStart), uint64(gotEnd))
	}

	// The kernel image line: kind=kernel and kernel_version present.
	kern := lines[4]
	if kern["type"] != "image" || kern["kind"] != "kernel" {
		t.Fatalf("line[4] = %v, want image/kernel", kern)
	}
	if kern["kernel_version"] != "Darwin Kernel Version 26.5" {
		t.Fatalf("kernel kernel_version = %v", kern["kernel_version"])
	}
	// A non-dylib image must not carry dsc_uuid (omitempty).
	if _, ok := kern["dsc_uuid"]; ok {
		t.Fatalf("kernel image unexpectedly carries dsc_uuid: %v", kern)
	}
}

// TestDBAccumulatorMatchesGraph verifies the visitor rebuilds the same nested
// model graph the daemon database persists.
func TestDBAccumulatorMatchesGraph(t *testing.T) {
	ipsw := &model.Ipsw{ID: "id"}
	acc := newDBAccumulator(ipsw)

	visit := []*scanImage{
		{Kind: "dsc", DSCUUID: "DSC1", SharedRegionStart: 0x1800},
		{Kind: "dylib", DSCUUID: "DSC1", Macho: &model.Macho{UUID: "D1", Symbols: []*model.Symbol{{Start: 1, End: 2}}}},
		// Fileset kernel: container (no symbols) then a kext.
		{Kind: "kernel", IsFileset: true, KernelVersion: "v1", Macho: &model.Macho{UUID: "KC1"}},
		{Kind: "kext", KernelUUID: "KC1", Macho: &model.Macho{UUID: "KX1", Symbols: []*model.Symbol{{Start: 3, End: 4}}}},
		// Non-fileset kernel: container is also the only kext, even when symbol-less.
		{Kind: "kernel", KernelVersion: "v2", Macho: &model.Macho{UUID: "KC2"}},
		{Kind: "macho", Macho: &model.Macho{UUID: "FS1", Symbols: []*model.Symbol{{Start: 7, End: 8}}}},
	}
	for _, img := range visit {
		if err := acc.visit(img); err != nil {
			t.Fatalf("visit %s: %v", img.Kind, err)
		}
	}

	if len(ipsw.DSCs) != 1 || ipsw.DSCs[0].UUID != "DSC1" || ipsw.DSCs[0].SharedRegionStart != 0x1800 {
		t.Fatalf("unexpected DSCs: %+v", ipsw.DSCs)
	}
	if len(ipsw.DSCs[0].Images) != 1 || ipsw.DSCs[0].Images[0].UUID != "D1" {
		t.Fatalf("unexpected DSC images: %+v", ipsw.DSCs[0].Images)
	}
	if len(ipsw.Kernels) != 2 {
		t.Fatalf("expected 2 kernelcaches, got %d", len(ipsw.Kernels))
	}
	// Fileset kernel: container has no symbols, so its only kext is KX1.
	kc1 := ipsw.Kernels[0]
	if kc1.UUID != "KC1" || kc1.Version != "v1" || len(kc1.Kexts) != 1 || kc1.Kexts[0].UUID != "KX1" {
		t.Fatalf("unexpected fileset kernel: %+v / kexts=%+v", kc1, kc1.Kexts)
	}
	// Non-fileset kernel: container is itself the single kext.
	kc2 := ipsw.Kernels[1]
	if kc2.UUID != "KC2" || kc2.Version != "v2" || len(kc2.Kexts) != 1 || kc2.Kexts[0].UUID != "KC2" {
		t.Fatalf("unexpected non-fileset kernel: %+v / kexts=%+v", kc2, kc2.Kexts)
	}
	if len(ipsw.FileSystem) != 1 || ipsw.FileSystem[0].UUID != "FS1" {
		t.Fatalf("unexpected file system: %+v", ipsw.FileSystem)
	}
}

func TestRescanTargetDoesNotShareScannedGraph(t *testing.T) {
	existing := &model.Ipsw{
		ID:      "id",
		Name:    "restore.ipsw",
		Version: "26.0",
		BuildID: "23A1",
		Devices: []*model.Device{
			{Name: "iPhone18,1"},
		},
		Kernels:    []*model.Kernelcache{{UUID: "old-kernel"}},
		DSCs:       []*model.DyldSharedCache{{UUID: "old-dsc"}},
		FileSystem: []*model.Macho{{UUID: "old-fs"}},
	}

	replacement := rescanTarget(existing)
	if replacement.ID != existing.ID ||
		replacement.Name != existing.Name ||
		replacement.Version != existing.Version ||
		replacement.BuildID != existing.BuildID {
		t.Fatalf("replacement metadata = %+v, want %+v", replacement, existing)
	}
	if len(replacement.Devices) != 1 || replacement.Devices[0].Name != "iPhone18,1" {
		t.Fatalf("replacement devices = %+v, want existing devices copied", replacement.Devices)
	}
	if len(replacement.Kernels) != 0 || len(replacement.DSCs) != 0 || len(replacement.FileSystem) != 0 {
		t.Fatalf("replacement scan graph should start empty: %+v", replacement)
	}

	replacement.Kernels = append(replacement.Kernels, &model.Kernelcache{UUID: "new-kernel"})
	if len(existing.Kernels) != 1 || existing.Kernels[0].UUID != "old-kernel" {
		t.Fatalf("existing kernels mutated: %+v", existing.Kernels)
	}
}

func TestOptionalVolumePresentDistinguishesAbsentFromInvalid(t *testing.T) {
	present, err := optionalVolumePresent(testVolumeInfo(
		map[string]string{"Cryptex1,AppOS": "app.dmg"},
	), "app")
	if err != nil || !present {
		t.Fatalf("present app volume = %t, err=%v; want present with no error", present, err)
	}

	present, err = optionalVolumePresent(testVolumeInfo(map[string]string{}), "app")
	if err != nil || present {
		t.Fatalf("absent app volume = %t, err=%v; want absent with no error", present, err)
	}

	present, err = optionalVolumePresent(testVolumeInfo(
		map[string]string{"Cryptex1,AppOS": "app1.dmg"},
		map[string]string{"Cryptex1,AppOS": "app2.dmg"},
	), "app")
	if err == nil || present || !strings.Contains(err.Error(), "multiple AppOS DMGs") {
		t.Fatalf("invalid app volume = %t, err=%v; want propagated invalid-manifest error", present, err)
	}
}

func testVolumeInfo(manifests ...map[string]string) *info.Info {
	buildIdentities := make([]plist.BuildIdentity, 0, len(manifests))
	for _, manifest := range manifests {
		buildIdentity := plist.BuildIdentity{
			Manifest: make(map[string]plist.IdentityManifest, len(manifest)),
		}
		for key, path := range manifest {
			buildIdentity.Manifest[key] = plist.IdentityManifest{
				Info: map[string]any{"Path": path},
			}
		}
		buildIdentities = append(buildIdentities, buildIdentity)
	}
	return &info.Info{
		Plists: &plist.Plists{
			BuildManifest: &plist.BuildManifest{
				BuildIdentities: buildIdentities,
			},
		},
	}
}

// TestPlatformFromInfo checks platform derivation from supported product types.
func TestPlatformFromInfo(t *testing.T) {
	cases := []struct {
		device string
		want   model.Platform
	}{
		{"iPhone18,1", model.PlatformIOS},
		{"iPad14,1", model.PlatformIOS},
		{"Macmini9,1", model.PlatformMacOS},
		{"AppleTV11,1", model.PlatformTvOS},
		{"Watch7,1", model.PlatformWatchOS},
		{"RealityDevice14,1", model.PlatformVisionOS},
	}
	for _, tc := range cases {
		inf := &info.Info{
			Plists: &plist.Plists{
				BuildManifest: &plist.BuildManifest{SupportedProductTypes: []string{tc.device}},
			},
		}
		if got := platformFromInfo(inf); got != tc.want {
			t.Errorf("platformFromInfo(%s) = %v, want %v", tc.device, got, tc.want)
		}
	}
}

// TestEmitterFileSystemKernelIsKernelClass is the regression for the darwin-db
// ingest failure on the arm64e macOS file-system kernel (the image record is the
// one captured from the failing run; the symbol is synthetic and inside its text
// range). Images are built the way scanMachosInMount builds them, so the test
// covers both the classification and the stream rendering.
func TestEmitterFileSystemKernelIsKernelClass(t *testing.T) {
	cases := []struct {
		name                     string
		path                     string
		arch                     string
		textStart, textEnd       uint64
		symStart, symEnd         uint64
		wantKind, wantPath       string
		wantStart, wantEnd       uint64
		wantSymStart, wantSymEnd uint64
	}{
		{
			name:      "arm64e file-system kernel",
			path:      "/root/System/Library/Kernels/kernel.release.t6000",
			arch:      "arm64e",
			textStart: 0xfffffe0007004000, textEnd: 0xfffffe000711c000,
			symStart: 0xfffffe0007005980, symEnd: 0xfffffe0007005a00,
			wantKind: "kernel", wantPath: "/System/Library/Kernels/kernel.release.t6000",
			wantStart: 0x7ffffe0007004000, wantEnd: 0x7ffffe000711c000,
			wantSymStart: 0x7ffffe0007005980, wantSymEnd: 0x7ffffe0007005a00,
		},
		{
			name:      "x86_64 file-system kernel",
			path:      "/root/System/Library/Kernels/kernel",
			arch:      "x86_64",
			textStart: 0xffffff8000200000, textEnd: 0xffffff8000bfc000,
			symStart: 0xffffff8000202000, symEnd: 0xffffff8000202080,
			wantKind: "kernel", wantPath: "/System/Library/Kernels/kernel",
			wantStart: 0x7fffff8000200000, wantEnd: 0x7fffff8000bfc000,
			wantSymStart: 0x7fffff8000202000, wantSymEnd: 0x7fffff8000202080,
		},
		{
			name:      "x86_64 kernel collection",
			path:      "/root/System/Library/KernelCollections/BootKernelExtensions.kc",
			arch:      "x86_64",
			textStart: 0xffffff8000200000, textEnd: 0xffffff8000bfc000,
			symStart: 0xffffff8000202000, symEnd: 0xffffff8000202080,
			wantKind: "kernel", wantPath: "/System/Library/KernelCollections/BootKernelExtensions.kc",
			wantStart: 0x7fffff8000200000, wantEnd: 0x7fffff8000bfc000,
			wantSymStart: 0x7fffff8000202000, wantSymEnd: 0x7fffff8000202080,
		},
		{
			name:      "kernel-space macho outside the kernel paths is untouched",
			path:      "/root/System/Library/Extensions/Synthetic.kext/Contents/MacOS/Synthetic",
			arch:      "arm64e",
			textStart: 0xfffffe0007004000, textEnd: 0xfffffe000711c000,
			symStart: 0xfffffe0007005980, symEnd: 0xfffffe0007005a00,
			wantKind: "macho", wantPath: "/root/System/Library/Extensions/Synthetic.kext/Contents/MacOS/Synthetic",
			wantStart: 0xfffffe0007004000, wantEnd: 0xfffffe000711c000,
			wantSymStart: 0xfffffe0007005980, wantSymEnd: 0xfffffe0007005a00,
		},
		{
			name:      "kernel path without kernel-space text is untouched",
			path:      "/root/System/Library/Kernels/kernel",
			arch:      "x86_64",
			textStart: 0x100000000, textEnd: 0x100004000,
			symStart: 0x100001000, symEnd: 0x100001040,
			wantKind: "macho", wantPath: "/root/System/Library/Kernels/kernel",
			wantStart: 0x100000000, wantEnd: 0x100004000,
			wantSymStart: 0x100001000, wantSymEnd: 0x100001040,
		},
		{
			name:      "user-space macho is untouched",
			path:      "/root/usr/bin/sh",
			arch:      "arm64e",
			textStart: 0x100000000, textEnd: 0x100004000,
			symStart: 0x100001000, symEnd: 0x100001040,
			wantKind: "macho", wantPath: "/root/usr/bin/sh",
			wantStart: 0x100000000, wantEnd: 0x100004000,
			wantSymStart: 0x100001000, wantSymEnd: 0x100001040,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			em := newJSONLEmitter(&buf)
			if err := em.image(&scanImage{
				Kind:       "macho",
				CPU:        tc.arch,
				Arch:       tc.arch,
				KernelPath: fileSystemKernelPath(tc.path, tc.textStart),
				Macho: &model.Macho{
					UUID:      "12A0D395-DBB9-3050-B357-F0F9F3185660",
					Path:      model.Path{Path: tc.path},
					TextStart: tc.textStart,
					TextEnd:   tc.textEnd,
					Symbols: []*model.Symbol{
						{Name: model.Name{Name: "_synthetic_entry"}, Start: tc.symStart, End: tc.symEnd},
					},
				},
			}); err != nil {
				t.Fatalf("emit: %v", err)
			}

			lines := rawLines(t, buf.Bytes())
			if len(lines) != 2 {
				t.Fatalf("expected image + symbol line, got %d: %s", len(lines), buf.String())
			}
			// Typed decode: uint64 addresses above 2^53 would not survive float64.
			var img imageLine
			var sym symbolLine
			if err := json.Unmarshal(lines[0], &img); err != nil {
				t.Fatalf("decode image line: %v", err)
			}
			if err := json.Unmarshal(lines[1], &sym); err != nil {
				t.Fatalf("decode symbol line: %v", err)
			}
			if img.Type != "image" || img.Kind != tc.wantKind || img.Path != tc.wantPath || img.Arch != tc.arch {
				t.Fatalf("image = %+v, want kind=%s path=%s arch=%s", img, tc.wantKind, tc.wantPath, tc.arch)
			}
			if img.TextStart != tc.wantStart || img.TextEnd != tc.wantEnd {
				t.Fatalf("image text range = [%#x,%#x), want [%#x,%#x)", img.TextStart, img.TextEnd, tc.wantStart, tc.wantEnd)
			}
			if sym.Type != "symbol" || sym.ImageUUID != img.UUID {
				t.Fatalf("symbol = %+v, want symbol for image %s", sym, img.UUID)
			}
			if sym.Start != tc.wantSymStart || sym.End != tc.wantSymEnd {
				t.Fatalf("symbol range = [%#x,%#x), want [%#x,%#x)", sym.Start, sym.End, tc.wantSymStart, tc.wantSymEnd)
			}
		})
	}
}

// TestEmitterEmitsEachOccurrenceOnce pins that an image occurrence (UUID, kind,
// path, text range, arch, DSC) and a DSC container are written once per scan:
// a release and a research kernelcache in one IPSW embed the same kexts, and
// a second emission with a different symbol set would leave consumers keyed by
// occurrence with two conflicting streams.
func TestEmitterEmitsEachOccurrenceOnce(t *testing.T) {
	var buf bytes.Buffer
	em := newJSONLEmitter(&buf)

	kext := func(kernelUUID, symbol string) *scanImage {
		return &scanImage{
			Kind:       "kext",
			CPU:        "arm64e",
			Arch:       "arm64e",
			KernelUUID: kernelUUID,
			Macho: &model.Macho{
				UUID:      "KEXT-UUID",
				Path:      model.Path{Path: "com.apple.kernel"},
				TextStart: 0xFFFFFFF007004000,
				TextEnd:   0xFFFFFFF007804000,
				Symbols: []*model.Symbol{
					{Name: model.Name{Name: symbol}, Start: 0x7004000, End: 0x7004100},
				},
			},
		}
	}
	kernel := func(uuid, path string) *scanImage {
		return &scanImage{
			Kind:          "kernel",
			CPU:           "arm64e",
			Arch:          "arm64e",
			IsFileset:     true,
			KernelVersion: "Darwin Kernel Version 25.6.0",
			Macho: &model.Macho{
				UUID:      uuid,
				Path:      model.Path{Path: path},
				TextStart: 0xFFFFFFF007000000,
				TextEnd:   0xFFFFFFF007004000,
			},
		}
	}

	for _, img := range []*scanImage{
		{Kind: "dsc", DSCUUID: "DSC-UUID", SharedRegionStart: 0x180000000},
		{Kind: "dsc", DSCUUID: "DSC-UUID", SharedRegionStart: 0x180000000},
		kernel("RELEASE-KC", "kernelcache.release.iphone17"),
		kext("RELEASE-KC", "ipc_port_free"),
		kernel("RESEARCH-KC", "kernelcache.research.iphone17"),
		kext("RESEARCH-KC", "func_fffffff007004000"),
	} {
		if err := em.image(img); err != nil {
			t.Fatalf("emit %s: %v", img.Kind, err)
		}
	}

	lines := decodeLines(t, buf.Bytes())
	var got []string
	for _, line := range lines {
		switch line["type"] {
		case "dsc":
			got = append(got, "dsc:"+line["uuid"].(string))
		case "image":
			got = append(got, line["kind"].(string)+":"+line["uuid"].(string))
		case "symbol":
			got = append(got, "symbol:"+line["name"].(string))
		}
	}
	want := []string{
		"dsc:DSC-UUID",
		"kernel:RELEASE-KC",
		"kext:KEXT-UUID",
		"symbol:ipc_port_free",
		"kernel:RESEARCH-KC",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("emitted lines = %v, want %v", got, want)
	}
}
