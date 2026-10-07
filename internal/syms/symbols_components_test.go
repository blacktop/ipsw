package syms

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/internal/model"
)

const componentManifestSample = `<?xml version="1.0"?><plist version="1.0"><dict>
<key>ProductVersion</key><string>99.0</string><key>ProductBuildVersion</key><string>99A1</string>
<key>SupportedProductTypes</key><array><string>Mac99,1</string></array>
<key>BuildIdentities</key><array><dict><key>ApProductType</key><string>Mac99,1</string>
<key>Info</key><dict><key>DeviceClass</key><string>boarda</string><key>Variant</key><string>Customer Erase Install (IPSW)</string></dict>
<key>Manifest</key><dict>
<key>OS</key><dict><key>Info</key><dict><key>Path</key><string>os.dmg</string></dict></dict>
<key>Cryptex1,SystemOS</key><dict><key>Info</key><dict><key>Path</key><string>system.dmg</string></dict></dict>
<key>Ap,ExclaveOS</key><dict><key>Info</key><dict><key>Path</key><string>exclave.dmg</string></dict></dict>
<key>KernelCache</key><dict><key>Info</key><dict><key>Path</key><string>kernelcache.release.test</string></dict></dict>
</dict></dict></array></dict></plist>`

func componentSource(t *testing.T, members ...string) string {
	t.Helper()
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	for _, name := range members {
		entry, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		data := "synthetic component payload"
		if name == "BuildManifest.plist" {
			data = componentManifestSample
		}
		if _, err := io.WriteString(entry, data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "source.ipsw")
	if err := os.WriteFile(path, archive.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func prepareTestComponent(t *testing.T, name, path, variant string, families ...string) *PreparedSymbolsComponent {
	t.Helper()
	source := componentSource(t, "BuildManifest.plist", path)
	p, err := PrepareComponentJSONL(&JSONLConfig{IPSW: source}, SymbolsComponentSelection{name, path, variant, families})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestComponentSourceAndSelectionBinding(t *testing.T) {
	p := prepareTestComponent(t, "KernelCache", "kernelcache.release.test", "release", "kernel")
	raw, err := os.ReadFile(p.cfg.IPSW)
	if err != nil {
		t.Fatal(err)
	}
	if p.start.Source.SHA256 != fmt.Sprintf("%x", sha256.Sum256(raw)) ||
		p.start.Source.LegacySHA1 != fmt.Sprintf("%x", sha1.Sum(raw)) || p.start.Source.Length != int64(len(raw)) ||
		p.start.BuildManifest.SHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte(componentManifestSample))) ||
		p.start.BuildManifest.Length != len(componentManifestSample) {
		t.Fatalf("source identity is not bound to bytes: %+v", p.start)
	}

	selection := SymbolsComponentSelection{"KernelCache", "kernelcache.release.test", "release", []string{"kernel"}}
	for _, tc := range []struct {
		name    string
		members []string
		change  func(*JSONLConfig, *SymbolsComponentSelection)
	}{
		{"missing manifest", []string{"kernelcache.release.test"}, nil},
		{"duplicate manifest", []string{"BuildManifest.plist", "BuildManifest.plist", "kernelcache.release.test"}, nil},
		{"missing member", []string{"BuildManifest.plist"}, nil},
		{"duplicate member", []string{"BuildManifest.plist", "kernelcache.release.test", "kernelcache.release.test"}, nil},
		{"sibling basename", []string{"BuildManifest.plist", "other/kernelcache.release.test"}, nil},
		{"manifest mismatch", []string{"BuildManifest.plist", "kernelcache.release.other"}, func(_ *JSONLConfig, s *SymbolsComponentSelection) { s.Path = "kernelcache.release.other" }},
		{"untrusted info", []string{"BuildManifest.plist", "kernelcache.release.other"}, func(c *JSONLConfig, s *SymbolsComponentSelection) {
			s.Path = "kernelcache.release.other"
			c.Info = testVolumeInfo(map[string]string{"KernelCache": "kernelcache.release.other"})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &JSONLConfig{IPSW: componentSource(t, tc.members...)}
			sel := selection
			if tc.change != nil {
				tc.change(cfg, &sel)
			}
			var output bytes.Buffer
			if err := ScanComponentJSONL(cfg, sel, &output); err == nil || output.Len() != 0 {
				t.Fatalf("invalid selection emitted output: err=%v body=%s", err, &output)
			}
		})
	}
}

func TestComponentOptionsRejectUnsupportedSelectionsBeforeIO(t *testing.T) {
	for _, sel := range []SymbolsComponentSelection{
		{Name: "unknown", Path: "os.dmg", Families: []string{"filesystem"}},
		{Name: "OS", Path: "os.dmg", Families: []string{"filesystem"}},
		{Name: "OS", Path: "os.dmg", Families: []string{"kernel"}},
		{Name: "Cryptex1,SystemOS", Path: "system.dmg", Families: []string{"dsc", "filesystem"}},
		{Name: "Cryptex1,AppOS", Path: "app.dmg", Families: []string{"filesystem"}},
		{Name: "Ap,ExclaveOS", Path: "exclave.dmg", Families: []string{"dsc"}},
		{Name: "Ap,ExclaveOS", Path: "exclave.dmg", Families: []string{"filesystem"}},
		{Name: "KernelCache", Path: "../kernelcache.release.test", Variant: "release", Families: []string{"kernel"}},
		{Name: "KernelCache", Path: "kernelcache.release.test", Variant: "release"},
		{Name: "KernelCache", Path: "kernelcache.release.test", Variant: "release", Families: []string{"unknown"}},
		{Name: "KernelCache", Path: "kernelcache.release.test", Variant: "release", Families: []string{"kernel", "kernel"}},
		{Name: "KernelCache", Path: "kernelcache.development.test", Variant: "development", Families: []string{"kernel"}},
		{Name: "KernelCache", Path: "kernelcache.release.test", Variant: "research", Families: []string{"kernel"}},
		{Name: "KernelCache", Path: "kernelcache.release.test", Variant: "release", Families: []string{"dsc"}},
		{Name: "KernelCache", Path: "kernelcache.release.test", Variant: "release", Families: []string{"filesystem"}},
		{Name: "KernelCache", Path: "kernelcache.release.test", Variant: "release", Families: []string{"kernel", "dsc"}},
		{Name: "KernelCache", Path: "kernelcache.release.test", Variant: "release", Families: []string{"kernel", "filesystem"}},
	} {
		var output bytes.Buffer
		err := ScanComponentJSONL(&JSONLConfig{IPSW: filepath.Join(t.TempDir(), "missing.ipsw")}, sel, &output)
		if err == nil || strings.Contains(err.Error(), "calculate component source identity") || output.Len() != 0 {
			t.Errorf("unsupported selection reached source I/O: selection=%+v err=%v output=%s", sel, err, &output)
		}
	}
	valid := SymbolsComponentSelection{"KernelCache", "kernelcache.release.test", "release", []string{"kernel"}}
	for _, cfg := range []*JSONLConfig{nil, {Device: "boarda"}, {Facts: true}, {FactsBoards: []string{}}} {
		if err := ValidateComponentOptions(cfg, valid); err == nil {
			t.Errorf("accepted incompatible options %+v", cfg)
		}
	}
	for _, variant := range []string{"release", "research"} {
		valid.Path, valid.Variant = "kernelcache."+variant+".test", variant
		if err := ValidateComponentOptions(&JSONLConfig{}, valid); err != nil {
			t.Errorf("recognized kernel variant %q rejected: %v", variant, err)
		}
	}
}

func TestComponentOccurrencesKeepEnrichedPayloadAndParents(t *testing.T) {
	var ids []string
	for _, variant := range []string{"release", "research"} {
		component := symbolsComponentDescriptor{Key: variant, Name: "KernelCache", Path: "kernelcache." + variant + ".test", Variant: variant}
		var wire bytes.Buffer
		em := newSymbolsComponentEmitter(&wire, component, []string{"kernel"})
		image := &scanImage{Kind: "kext", ComponentPath: component.Path, KernelUUID: "KERNEL-A", CPU: "arm64e", Arch: "arm64e",
			Macho: &model.Macho{UUID: "SAME-KEXT", Path: model.Path{Path: "com.example.driver"}, TextStart: 4096, TextEnd: 8192,
				Symbols: []*model.Symbol{{Name: model.Name{Name: variant + "_symbol"}, Start: 4100, End: 4104}}}}
		if err := em.image("kernel", image); err != nil {
			t.Fatal(err)
		}
		if err := em.image("kernel", image); err != nil { // same precise occurrence is suppressed
			t.Fatal(err)
		}
		image.KernelUUID = "KERNEL-B"
		if err := em.image("kernel", image); err != nil {
			t.Fatal(err)
		}
		lines := rawLines(t, wire.Bytes())
		if len(lines) != 4 || !bytes.Contains(wire.Bytes(), []byte(variant+"_symbol")) {
			t.Fatalf("component payload collapsed: %s", &wire)
		}
		var firstID string
		for idx, raw := range lines {
			var record struct{ Type, OccurrenceID, ComponentKey, KernelUUID, Family string }
			// JSON snake_case fields are explicit for the identity assertions.
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(fields["occurrence_id"], &record.OccurrenceID); err != nil {
				t.Fatal(err)
			}
			if idx%2 == 0 {
				if idx == 2 && record.OccurrenceID == firstID {
					t.Fatal("parent kernel UUID missing from occurrence identity")
				}
				firstID = record.OccurrenceID
				ids = append(ids, firstID)
			} else if record.OccurrenceID != firstID {
				t.Fatal("symbol does not name the current precise image")
			}
		}
		if got := em.completion(); got.Images != 2 || got.Symbols != 2 || got.Records != 4 {
			t.Fatalf("counts=%+v", got)
		}
	}
	if slices.Contains(ids[:2], ids[2]) || slices.Contains(ids[:2], ids[3]) {
		t.Fatal("source component missing from occurrence identity")
	}
}

func TestComponentKernelStreamCompletion(t *testing.T) {
	p := prepareTestComponent(t, "KernelCache", "kernelcache.release.test", "release", "kernel")
	var wire bytes.Buffer
	err := p.scan(&wire, func(visit func(string, *scanImage) error) error {
		if err := visit("kernel", &scanImage{Kind: "kernel", ComponentPath: p.start.Component.Path,
			Macho: &model.Macho{UUID: "KERNEL", Path: model.Path{Path: "kernelcache.release.test"}}}); err != nil {
			return err
		}
		return visit("kernel", &scanImage{Kind: "kext", ComponentPath: p.start.Component.Path, KernelUUID: "KERNEL",
			Macho: &model.Macho{UUID: "KEXT", Path: model.Path{Path: "com.example.driver"},
				Symbols: []*model.Symbol{{Name: model.Name{Name: "kernel_symbol"}, Start: 4096, End: 4100}}}})
	})
	if err != nil {
		t.Fatal(err)
	}
	assertComponentCompletion(t, wire.Bytes(), 3, 0, 2, 1)
}

func assertComponentCompletion(t *testing.T, wire []byte, records, dscs, images, symbols uint64) {
	t.Helper()
	lines := bytes.Split(bytes.TrimSuffix(wire, []byte{'\n'}), []byte{'\n'})
	var complete symbolsComponentCompleteLine
	if err := json.Unmarshal(lines[len(lines)-1], &complete); err != nil {
		t.Fatal(err)
	}
	var data []byte
	for _, line := range lines[1 : len(lines)-1] {
		data = append(data, line...)
		data = append(data, '\n')
	}
	if complete.Type != "symbols_component_complete" || complete.Status != "successful" || !complete.RequiresSuccessfulProcessExit ||
		complete.Records != records || complete.DSCs != dscs || complete.Images != images || complete.Symbols != symbols ||
		complete.RecordsSHA256 != fmt.Sprintf("%x", sha256.Sum256(data)) {
		t.Fatalf("invalid completion: %+v", complete)
	}
	var sum componentRecordCounts
	for _, op := range complete.Operations {
		if op.ComponentKey != complete.ComponentKey || op.Status != "successful" {
			t.Fatalf("invalid operation: %+v", op)
		}
		sum.Records += op.Records
		sum.DSCs += op.DSCs
		sum.Images += op.Images
		sum.Symbols += op.Symbols
	}
	if sum != complete.componentRecordCounts {
		t.Fatalf("operations do not reconcile: %+v", complete)
	}
}

func TestComponentEmptySuccessAndTerminalFailures(t *testing.T) {
	p := prepareTestComponent(t, "KernelCache", "kernelcache.release.test", "release", "kernel")
	var empty bytes.Buffer
	if err := p.scan(&empty, func(func(string, *scanImage) error) error { return nil }); err != nil {
		t.Fatal(err)
	}
	assertComponentCompletion(t, empty.Bytes(), 0, 0, 0, 0)
	if !bytes.Contains(empty.Bytes(), []byte(`"family":"kernel","status":"successful","records":0`)) {
		t.Fatal("successful empty operation omitted")
	}

	wantErr := errors.New("injected scan or cleanup failure")
	var failed bytes.Buffer
	if err := p.scan(&failed, func(func(string, *scanImage) error) error { return wantErr }); !errors.Is(err, wantErr) || bytes.Contains(failed.Bytes(), []byte(`symbols_component_complete`)) {
		t.Fatalf("failure certified: err=%v wire=%s", err, &failed)
	}
	for _, failCall := range []int{1, 2} {
		writer := &componentFailWriter{failCall: failCall, err: wantErr}
		err := p.scan(writer, func(func(string, *scanImage) error) error { return nil })
		if !errors.Is(err, wantErr) || bytes.Contains(writer.Bytes(), []byte(`symbols_component_complete`)) {
			t.Fatalf("writer failure certified: call=%d err=%v wire=%s", failCall, err, writer.Bytes())
		}
	}
	var changed bytes.Buffer
	err := p.scan(&changed, func(func(string, *scanImage) error) error {
		return os.WriteFile(p.cfg.IPSW, []byte("changed source"), 0600)
	})
	if err == nil || !strings.Contains(err.Error(), "source identity") || bytes.Contains(changed.Bytes(), []byte(`symbols_component_complete`)) {
		t.Fatalf("changed source certified: err=%v wire=%s", err, &changed)
	}
	var beforeStart bytes.Buffer
	if err := p.Scan(&beforeStart); err == nil || beforeStart.Len() != 0 {
		t.Fatalf("changed source emitted start: %v %s", err, &beforeStart)
	}
}

type componentFailWriter struct {
	bytes.Buffer
	call, failCall int
	err            error
}

func (w *componentFailWriter) Write(data []byte) (int, error) {
	w.call++
	if w.call >= w.failCall {
		return 0, w.err
	}
	return w.Buffer.Write(data)
}
