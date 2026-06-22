package crashlog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fatih/color"
)

// microstackshotSample is a trimmed but structurally faithful SymptomsIO (145)
// disk-writes report: JSON header line + Microstackshots text body. Kept inline
// so the parser is covered in CI (the full real fixtures live under the
// gitignored test-caches/).
const microstackshotSample = `{"bug_type":"145","os_version":"iPhone OS 26.0 (23A5297m)","timestamp":"2025-07-24 16:05:52.00 -0600","app_name":"analyticsd","name":"analyticsd","incident_id":"BACD377F-C0BE-40C0-A6F5-014150A9003B"}
Date/Time:        2025-07-24 13:42:43.586 -0600
OS Version:       iPhone OS 26.0 (Build 23A5297m)
Architecture:     arm64e
Data Source:      Microstackshots
Shared Cache:     90BBDE82-938A-384B-8837-ED0C790BC5C9 slid base address 0x19c578000, slide 0x1c578000
Command:          analyticsd
Path:             /System/Library/PrivateFrameworks/CoreAnalytics.framework/Support/analyticsd
PID:              122

Event:            disk writes
Action taken:     none
Writes:           1073.74 MB of file backed memory dirtied over 8588 seconds, exceeding limit of 12.43 KB per second over 86400 seconds
Writes limit:     1073.74 MB
Limit duration:   86400s

Hardware model:   iPhone17,1
Memory size:      7.47 GB

Heaviest stack for the target process:
  61  ??? (libsystem_pthread.dylib + 2240) [0x22f72b8c0]
  52  ??? (analyticsd + 6324) [0x1007698b4]


Powerstats for:   analyticsd [122]
UUID:             27E9C3C9-3AD1-3168-8D1A-52416AE93937
`

func TestOpenMicrostackshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "diskwrites.ips")
	if err := os.WriteFile(path, []byte(microstackshotSample), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	ms, err := OpenMicrostackshot(path, &Config{})
	if err != nil {
		t.Fatalf("OpenMicrostackshot: %v", err)
	}
	if ms.Header.BugType != "145" {
		t.Errorf("BugType = %q, want 145", ms.Header.BugType)
	}
	if ms.Header.BugTypeDesc != "SymptomsIO" {
		t.Errorf("BugTypeDesc = %q, want SymptomsIO", ms.Header.BugTypeDesc)
	}
	if ms.Command != "analyticsd" || ms.PID != 122 {
		t.Errorf("Command/PID = %q/%d, want analyticsd/122", ms.Command, ms.PID)
	}
	if ms.Event != "disk writes" {
		t.Errorf("Event = %q, want \"disk writes\"", ms.Event)
	}
	if ms.Path != "/System/Library/PrivateFrameworks/CoreAnalytics.framework/Support/analyticsd" {
		t.Errorf("unexpected Path %q", ms.Path)
	}
	if !hasDetail(ms.EventDetail, "exceeding limit of") {
		t.Errorf("EventDetail missing the limit message: %#v", ms.EventDetail)
	}
	if len(ms.HeaviestStack) != 2 {
		t.Fatalf("HeaviestStack len = %d, want 2 (must stop before Powerstats)", len(ms.HeaviestStack))
	}
	f := ms.HeaviestStack[0]
	if f.Count != 61 || f.Image != "libsystem_pthread.dylib" || f.Offset != 2240 || f.Addr != 0x22f72b8c0 {
		t.Errorf("frame[0] = %+v, want count=61 image=libsystem_pthread.dylib offset=2240 addr=0x22f72b8c0", f)
	}
}

func TestParseFrame(t *testing.T) {
	cases := []struct {
		line string
		ok   bool
		want MicrostackFrame
	}{
		{"  61  ??? (libsystem_pthread.dylib + 2240) [0x22f72b8c0]", true, MicrostackFrame{61, "???", "libsystem_pthread.dylib", 2240, 0x22f72b8c0}},
		{"  52  ??? (analyticsd + 6324) [0x1007698b4]", true, MicrostackFrame{52, "???", "analyticsd", 6324, 0x1007698b4}},
		{"Powerstats for:   analyticsd [122]", false, MicrostackFrame{}},
		{"", false, MicrostackFrame{}},
	}
	for _, c := range cases {
		got, ok := parseFrame(c.line)
		if ok != c.ok {
			t.Errorf("parseFrame(%q) ok = %v, want %v", c.line, ok, c.ok)
			continue
		}
		if ok && got != c.want {
			t.Errorf("parseFrame(%q) = %+v, want %+v", c.line, got, c.want)
		}
	}
}

// TestMicrostackshotGolden pins the full render of the real fixture; it skips
// when the gitignored sample is absent (e.g. CI).
func TestMicrostackshotGolden(t *testing.T) {
	prev := color.NoColor
	color.NoColor = true
	t.Cleanup(func() { color.NoColor = prev })

	sample := filepath.Join("..", "..", "test-caches", "research", "crashlogs", "analyticsd.diskwrites_resource-2025-07-24-160552.ips")
	if _, err := os.Stat(sample); err != nil {
		t.Skipf("sample not available: %v", err)
	}
	ms, err := OpenMicrostackshot(sample, &Config{})
	if err != nil {
		t.Fatalf("OpenMicrostackshot: %v", err)
	}
	got := ms.String()
	goldenPath := filepath.Join("testdata", "golden", "145.golden")
	if updateGolden {
		if err := os.WriteFile(goldenPath, []byte(got), 0o644); err != nil {
			t.Fatalf("update golden: %v", err)
		}
		return
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if got != string(want) {
		t.Errorf("145 render drifted from golden; set UPDATE_GOLDEN=1 to refresh if intentional")
	}
}

func hasDetail(detail []string, substr string) bool {
	for _, d := range detail {
		if strings.Contains(d, substr) {
			return true
		}
	}
	return false
}
