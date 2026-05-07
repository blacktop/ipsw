package launchd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blacktop/go-plist"
)

func TestWalkVolumeLaunchdMachServices(t *testing.T) {
	root := t.TempDir()
	writePlist(t, root, "/System/Library/LaunchDaemons/com.apple.test.plist", map[string]any{
		"Label":              "com.apple.test",
		"CFBundleIdentifier": "com.apple.test.bundle",
		"ProgramArguments":   []string{"/usr/libexec/testd", "--flag"},
		"MachServices": map[string]any{
			"com.apple.test.b": true,
			"com.apple.test.a": map[string]any{"ResetAtClose": true},
		},
		"SandboxProfile": "testd",
		"POSIXSpawnType": "Adaptive",
		"RunAtLoad":      true,
	}, plist.XMLFormat)

	records, err := WalkVolume(root, "SystemOS")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	record := records[0]
	if record.SourceKind != SourceKindLaunchdDaemon {
		t.Fatalf("source kind = %q", record.SourceKind)
	}
	if record.Label != "com.apple.test" {
		t.Fatalf("label = %q", record.Label)
	}
	if record.BundleID != "com.apple.test.bundle" {
		t.Fatalf("bundle id = %q", record.BundleID)
	}
	if record.Program != "/usr/libexec/testd" {
		t.Fatalf("program = %q", record.Program)
	}
	if got, want := strings.Join(record.MachServices, ","), "com.apple.test.a,com.apple.test.b"; got != want {
		t.Fatalf("mach services = %q, want %q", got, want)
	}
	if record.SandboxProfile != "testd" {
		t.Fatalf("sandbox profile = %q", record.SandboxProfile)
	}
	if record.ServiceType != "Adaptive" {
		t.Fatalf("service type = %q", record.ServiceType)
	}
	if record.Extra["RunAtLoad"] != true {
		t.Fatalf("RunAtLoad missing from extra: %#v", record.Extra)
	}
	if _, ok := record.Extra["MachServices"]; ok {
		t.Fatalf("captured MachServices leaked into extra: %#v", record.Extra)
	}
	if _, ok := record.Extra["CFBundleIdentifier"]; ok {
		t.Fatalf("captured CFBundleIdentifier leaked into extra: %#v", record.Extra)
	}
}

func TestWalkVolumeXPCBundleLayouts(t *testing.T) {
	root := t.TempDir()
	writePlist(t, root, "/System/Library/PrivateFrameworks/Foo.framework/XPCServices/FooService.xpc/Info.plist", map[string]any{
		"CFBundleIdentifier": "com.apple.FooService",
		"CFBundleExecutable": "FooService",
		"XPCService": map[string]any{
			"ServiceType":         "Application",
			"SeatbeltProfiles":    []string{"foo-sandbox"},
			"JoinExistingSession": true,
		},
	}, plist.XMLFormat)
	writePlist(t, root, "/System/Library/PrivateFrameworks/Bar.framework/XPCServices/BarService.xpc/Contents/Info.plist", map[string]any{
		"CFBundleIdentifier": "com.apple.BarService",
		"CFBundleExecutable": "BarService",
		"XPCService": map[string]any{
			"ServiceType": "Application",
		},
	}, plist.XMLFormat)

	records, err := WalkVolume(root, "SystemOS")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}

	flat := findRecord(records, "/System/Library/PrivateFrameworks/Foo.framework/XPCServices/FooService.xpc/Info.plist")
	if flat == nil {
		t.Fatal("missing flat XPC record")
	}
	if flat.Program != "FooService" {
		t.Fatalf("flat program = %q", flat.Program)
	}
	if got := strings.Join(flat.MachServices, ","); got != "com.apple.FooService" {
		t.Fatalf("flat mach services = %q", got)
	}
	if flat.SandboxProfile != "foo-sandbox" {
		t.Fatalf("flat sandbox profile = %q", flat.SandboxProfile)
	}
	if flat.ServiceType != "Application" {
		t.Fatalf("flat service type = %q", flat.ServiceType)
	}
	xpcExtra, ok := flat.Extra["XPCService"].(map[string]any)
	if !ok || xpcExtra["JoinExistingSession"] != true {
		t.Fatalf("unexpected XPCService extra: %#v", flat.Extra["XPCService"])
	}
	if _, ok := xpcExtra["ServiceType"]; ok {
		t.Fatalf("captured ServiceType leaked into extra: %#v", xpcExtra)
	}

	contents := findRecord(records, "/System/Library/PrivateFrameworks/Bar.framework/XPCServices/BarService.xpc/Contents/Info.plist")
	if contents == nil {
		t.Fatal("missing Contents XPC record")
	}
	if contents.Program != "Contents/MacOS/BarService" {
		t.Fatalf("Contents program = %q", contents.Program)
	}
}

func TestWalkVolumeAppXPCAndPlainApp(t *testing.T) {
	root := t.TempDir()
	writePlist(t, root, "/Applications/HasService.app/Info.plist", map[string]any{
		"CFBundleIdentifier": "com.apple.HasService",
		"CFBundleExecutable": "HasService",
		"XPCService": map[string]any{
			"ServiceType": "Application",
		},
	}, plist.XMLFormat)
	writePlist(t, root, "/Applications/Plain.app/Info.plist", map[string]any{
		"CFBundleIdentifier": "com.apple.Plain",
		"CFBundleExecutable": "Plain",
	}, plist.XMLFormat)

	records, err := WalkVolume(root, "AppOS")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("expected only the app with XPCService, got %d records", len(records))
	}
	record := records[0]
	if record.SourceKind != SourceKindAppXPC {
		t.Fatalf("source kind = %q", record.SourceKind)
	}
	if record.Program != "HasService" {
		t.Fatalf("program = %q", record.Program)
	}
}

func TestWalkVolumeMissingProgram(t *testing.T) {
	root := t.TempDir()
	writePlist(t, root, "/System/Library/LaunchAgents/com.apple.noprogram.plist", map[string]any{
		"Label": "com.apple.noprogram",
	}, plist.XMLFormat)

	records, err := WalkVolume(root, "SystemOS")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Program != "" {
		t.Fatalf("program = %q", records[0].Program)
	}
}

func TestWalkVolumeProgramArgumentsKeepsEmptyFirstArgument(t *testing.T) {
	root := t.TempDir()
	writePlist(t, root, "/System/Library/LaunchDaemons/com.apple.emptyarg.plist", map[string]any{
		"Label":            "com.apple.emptyarg",
		"ProgramArguments": []any{"", "/usr/libexec/should-not-shift"},
	}, plist.XMLFormat)

	records, err := WalkVolume(root, "SystemOS")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Program != "" {
		t.Fatalf("program = %q, want empty ProgramArguments[0]", records[0].Program)
	}
}

func TestWalkVolumeParseErrorPassthrough(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "System/Library/LaunchAgents/bad.plist")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not a plist"), 0644); err != nil {
		t.Fatal(err)
	}

	records, err := WalkVolume(root, "SystemOS")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	record := records[0]
	if record.SourceKind != SourceKindLaunchdAgent {
		t.Fatalf("source kind = %q", record.SourceKind)
	}
	if record.PlistDigest == "" {
		t.Fatal("parse error record has empty digest")
	}
	if record.Extra["parse_error"] == "" {
		t.Fatalf("parse_error missing from extra: %#v", record.Extra)
	}
}

func TestEncodeJSONLDeterministic(t *testing.T) {
	records := []Record{
		{
			SourceKind:     SourceKindXPCBundle,
			PlistPath:      "/b.plist",
			Volume:         "SystemOS",
			PlistDigest:    "2",
			MachServices:   []string{"z", "a"},
			SandboxProfile: "",
			Extra: map[string]any{
				"array":       []any{"b", "a"},
				"dict":        map[string]any{"z": []any{"2", "1"}},
				"dsl<filter>": "kept literal",
			},
		},
		{
			SourceKind:  SourceKindLaunchdDaemon,
			PlistPath:   "/a.plist",
			Volume:      "AppOS",
			PlistDigest: "1",
			Extra:       map[string]any{},
		},
	}

	first, err := EncodeJSONL(records)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EncodeJSONL(records)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("encoding changed across runs:\n%s\n%s", first, second)
	}
	lines := bytes.Split(bytes.TrimSuffix(first, []byte("\n")), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
	if !bytes.Contains(lines[0], []byte(`"volume":"AppOS"`)) {
		t.Fatalf("records not sorted by volume/path: %s", first)
	}
	if !bytes.Contains(lines[0], []byte(`"mach_services":[]`)) {
		t.Fatalf("empty mach services encoded as non-array: %s", lines[0])
	}
	if !bytes.Contains(lines[1], []byte(`"mach_services":["a","z"]`)) {
		t.Fatalf("mach services not sorted: %s", lines[1])
	}
	if !bytes.Contains(lines[1], []byte(`"array":["a","b"]`)) {
		t.Fatalf("extra array not sorted: %s", lines[1])
	}
	if bytes.Contains(lines[1], []byte(`\u003c`)) || bytes.Contains(lines[1], []byte(`\u003e`)) {
		t.Fatalf("HTML-sensitive characters were escaped: %s", lines[1])
	}

	var decoded map[string]any
	if err := json.Unmarshal(lines[1], &decoded); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
}

func TestPlistDigestEquivalence(t *testing.T) {
	doc := map[string]any{
		"Label":     "com.apple.digest",
		"RunAtLoad": true,
		"MachServices": map[string]any{
			"com.apple.digest": true,
		},
	}
	xmlData, err := plist.Marshal(doc, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	binData, err := plist.Marshal(doc, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	_, xmlDigest, err := parsePlist(xmlData)
	if err != nil {
		t.Fatal(err)
	}
	_, binDigest, err := parsePlist(binData)
	if err != nil {
		t.Fatal(err)
	}
	if xmlDigest != binDigest {
		t.Fatalf("digest mismatch: xml=%s bin=%s", xmlDigest, binDigest)
	}
}

func writePlist(t *testing.T, root, rel string, doc map[string]any, format int) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(rel, "/")))
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	data, err := plist.Marshal(doc, format)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
}

func findRecord(records []Record, path string) *Record {
	for i := range records {
		if records[i].PlistPath == path {
			return &records[i]
		}
	}
	return nil
}
