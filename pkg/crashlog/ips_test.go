package crashlog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/fatih/color"
)

const jetsamSample = `{"bug_type":"298","timestamp":"2026-06-14 15:08:19.00 -0600","os_version":"iPhone OS 27.0 (24A5355q)","incident_id":"E0F926D5-4491-4F9F-84F6-83A7E90C43E9"}
{
  "build": "iPhone OS 27.0 (24A5355q)",
  "product": "iPhone18,1",
  "kernel": "Darwin Kernel Version 27.0.0: root:xnu-13361.0.0.502.1~1/RELEASE_ARM64_T8150",
  "bug_type": "298",
  "memoryStatus": {
    "compressorSize": 103177,
    "pageSize": 16384,
    "largestZone": "APFS_4K_OBJS",
    "largestZoneSize": 196640768,
    "uncompressed": 292998,
    "zoneMapSize": 601161728,
    "zoneMapCap": 4515479552,
    "memoryPages": {"active": 195361, "free": 11374, "wired": 244813, "anonymous": 209999, "fileBacked": 180593}
  },
  "largestProcess": "TGOnDeviceInferenceProviderServi",
  "processes": [
    {"pid": 76, "name": "backboardd", "states": ["active"], "priority": 170, "rpages": 19240, "lifetimeMax": 19240, "physicalPages": {"frozen_to_swap_pages": 6344}},
    {"pid": 44152, "name": "financed", "states": ["daemon","idle"], "priority": 0, "rpages": 804, "lifetimeMax": 804, "reason": "per-process-limit", "freeze_skip_reason:": "none", "csFlags": 570434305, "cpuTime": 0.387142, "physicalPages": {"internal": [567, 220]}}
  ]
}`

func writeJetsamSample(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "JetsamEvent.ips")
	if err := os.WriteFile(path, []byte(jetsamSample), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	return path
}

func TestOpenIPSJetsamEvent(t *testing.T) {
	path := writeJetsamSample(t)

	hdr, err := ParseHeader(path)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if hdr.BugType != "298" {
		t.Fatalf("BugType = %q, want 298", hdr.BugType)
	}
	if hdr.BugTypeDesc != "Jetsam" {
		t.Fatalf("BugTypeDesc = %q, want Jetsam", hdr.BugTypeDesc)
	}

	ips, err := OpenIPS(path, &Config{})
	if err != nil {
		t.Fatalf("OpenIPS: %v", err)
	}
	if ips.Jetsam == nil {
		t.Fatal("expected Jetsam payload, got nil")
	}
	j := ips.Jetsam
	if j.Product != "iPhone18,1" {
		t.Errorf("Product = %q, want iPhone18,1", j.Product)
	}
	if j.MemoryStatus.PageSize != 16384 {
		t.Errorf("PageSize = %d, want 16384", j.MemoryStatus.PageSize)
	}
	if j.MemoryStatus.LargestZone != "APFS_4K_OBJS" {
		t.Errorf("LargestZone = %q, want APFS_4K_OBJS", j.MemoryStatus.LargestZone)
	}
	if j.MemoryStatus.MemoryPages.Anonymous != 209999 {
		t.Errorf("MemoryPages.Anonymous = %d, want 209999", j.MemoryStatus.MemoryPages.Anonymous)
	}
	if len(j.Processes) != 2 {
		t.Fatalf("len(Processes) = %d, want 2", len(j.Processes))
	}

	var killed *JetsamProcess
	for idx := range j.Processes {
		if j.Processes[idx].Reason != "" {
			killed = &j.Processes[idx]
		}
	}
	if killed == nil {
		t.Fatal("no killed process found (expected one with a Reason)")
	}
	if killed.Name != "financed" || killed.PID != 44152 {
		t.Errorf("killed = %s [%d], want financed [44152]", killed.Name, killed.PID)
	}
	if killed.Reason != "per-process-limit" {
		t.Errorf("killed.Reason = %q, want per-process-limit", killed.Reason)
	}
	// the source key is "freeze_skip_reason:" with a trailing colon
	if killed.FreezeSkip != "none" {
		t.Errorf("killed.FreezeSkip = %q, want none (trailing-colon key decode)", killed.FreezeSkip)
	}
}

func TestJetsamRender(t *testing.T) {
	prev := color.NoColor
	color.NoColor = true
	t.Cleanup(func() { color.NoColor = prev })

	ips, err := OpenIPS(writeJetsamSample(t), &Config{})
	if err != nil {
		t.Fatalf("OpenIPS: %v", err)
	}
	out := ips.String()

	wantContains := []string{
		"Jetsam - iPhone18,1 iPhone OS 27.0 (24A5355q)",
		"Kernel: Darwin Kernel Version 27.0.0", // kernel build string in header
		"Killed Process: financed [44152]",
		"per-process-limit (exceeded its per-process memory limit)",
		"567 pages (8.9 MiB) resident / 220 pages (3.4 MiB) compressed", // physicalPages.internal split
		"CPU Time",
		"Largest Zone  APFS_4K_OBJS",
		"Top Memory Consumers (2 total)",
		"backboardd",                  // larger process sorts first
		"(killed: per-process-limit)", // killed marker in the consumer list
	}
	for _, w := range wantContains {
		if !strings.Contains(out, w) {
			t.Errorf("render missing %q\n--- output ---\n%s", w, out)
		}
	}

	// within the consumer list, the bigger process must be listed first
	consumers := out[strings.Index(out, "Top Memory Consumers"):]
	if strings.Index(consumers, "backboardd") > strings.Index(consumers, "financed") {
		t.Error("processes not sorted by resident memory (backboardd should precede financed)")
	}
}

func TestJetsamProcessFilter(t *testing.T) {
	prev := color.NoColor
	color.NoColor = true
	t.Cleanup(func() { color.NoColor = prev })

	path := writeJetsamSample(t)

	// a matching --proc filter reports "(matched of total)" and only that process
	matched, err := OpenIPS(path, &Config{Process: "financed"})
	if err != nil {
		t.Fatalf("OpenIPS: %v", err)
	}
	out := matched.String()
	if !strings.Contains(out, `Processes matching "financed" (1 of 2)`) {
		t.Errorf("filtered header missing matched/total count\n%s", out)
	}
	if strings.Contains(out, "backboardd") {
		t.Errorf("filtered output should not list non-matching processes\n%s", out)
	}

	// a --proc filter with no match returns an explicit message, not an empty list
	none, err := OpenIPS(path, &Config{Process: "ghost"})
	if err != nil {
		t.Fatalf("OpenIPS: %v", err)
	}
	out = none.String()
	if !strings.Contains(out, `no process matching "ghost" found in this report (2 total)`) {
		t.Errorf("empty filter should report no match\n%s", out)
	}

	// jetsam truncates names; a filter longer than the stored (truncated) name
	// must still match it (e.g. real "financed-daemon" vs stored "financed").
	trunc, err := OpenIPS(path, &Config{Process: "financed-helper-process"})
	if err != nil {
		t.Fatalf("OpenIPS: %v", err)
	}
	if out = trunc.String(); !strings.Contains(out, "financed") || strings.Contains(out, "no process matching") {
		t.Errorf("filter longer than truncated name should still match\n%s", out)
	}
}

func TestJetsamRenderEdgeCases(t *testing.T) {
	prev := color.NoColor
	color.NoColor = true
	t.Cleanup(func() { color.NoColor = prev })

	// nil payload (malformed report) must not panic
	nilIps := &Ips{Header: IpsMetadata{BugType: "298"}, Config: &Config{}}
	if out := nilIps.String(); !strings.Contains(out, "malformed JetsamEvent") {
		t.Errorf("nil Jetsam payload should report malformed, got %q", out)
	}

	// empty process list must render cleanly (no sorted[0] panic)
	path := filepath.Join(t.TempDir(), "empty.ips")
	data := []byte(`{"bug_type":"298","os_version":"iPhone OS 27.0 (24A5355q)"}
{"product":"iPhone18,1","processes":[]}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	ips, err := OpenIPS(path, &Config{})
	if err != nil {
		t.Fatalf("OpenIPS: %v", err)
	}
	if out := ips.String(); !strings.Contains(out, "Top Memory Consumers (0 total)") {
		t.Errorf("empty process list should render (0 total), got\n%s", out)
	}
}

func TestIBytesNonNeg(t *testing.T) {
	if got := iBytesNonNeg(196640768); got != "188 MiB" {
		t.Errorf("iBytesNonNeg(196640768) = %q, want \"188 MiB\"", got)
	}
	// a corrupt negative size must clamp to 0, not wrap to a ~16 EiB figure
	if got := iBytesNonNeg(-1); got != "0 B" {
		t.Errorf("iBytesNonNeg(-1) = %q, want \"0 B\" (no uint64 wrap)", got)
	}
}

func TestJetsamFrozenToSwap(t *testing.T) {
	prev := color.NoColor
	color.NoColor = true
	t.Cleanup(func() { color.NoColor = prev })

	// A killed process with frozen-to-swap pages should surface that line. Promote
	// backboardd (which carries frozen_to_swap_pages) to a killed process.
	sample := strings.Replace(jetsamSample,
		`"physicalPages": {"frozen_to_swap_pages": 6344}}`,
		`"reason": "vm-pageshortage", "physicalPages": {"frozen_to_swap_pages": 6344}}`, 1)
	path := filepath.Join(t.TempDir(), "frozen.ips")
	if err := os.WriteFile(path, []byte(sample), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	ips, err := OpenIPS(path, &Config{})
	if err != nil {
		t.Fatalf("OpenIPS: %v", err)
	}
	out := ips.String()
	if !strings.Contains(out, "Frozen to Swap  6,344 pages") {
		t.Errorf("expected frozen-to-swap line for killed process\n%s", out)
	}
}

func TestJetsamPages(t *testing.T) {
	if got := jetsamPages(804, 16384); got != "804 pages (13 MiB)" {
		t.Errorf("jetsamPages(804, 16384) = %q, want \"804 pages (13 MiB)\"", got)
	}
	// pageSize 0 falls back to the 16 KiB default rather than reporting 0 bytes
	if got := jetsamPages(1, 0); got != "1 pages (16 KiB)" {
		t.Errorf("jetsamPages(1, 0) = %q, want \"1 pages (16 KiB)\"", got)
	}
}

func TestCrashFrameAddrDSCSlide(t *testing.T) {
	// 309 report: image 0 is in-process (below the cache), image 1 is a
	// dyld_shared_cache dylib (base inside [sharedCache.base, base+size)).
	// Note source "P" even for the cache dylib, mirroring real reports.
	const payload = `{
		"sharedCache": {"base": 6979321856, "size": 1073741824, "uuid": "ff7119a7-f64d-305d-8135-7e6eb1c207d1"},
		"usedImages": [
			{"base": 4294967296, "name": "myapp", "source": "P", "size": 65536},
			{"base": 6984564736, "name": "libsystem_kernel.dylib", "source": "P", "size": 262144}
		],
		"threads": [
			{"triggered": true, "frames": [
				{"imageIndex": 0, "imageOffset": 4660},
				{"imageIndex": 1, "imageOffset": 64}
			]}
		]
	}`

	var p IPSPayload
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	procFrame := p.Threads[0].Frames[0] // runtime: 0x100000000 + 0x1234 = 0x100001234
	dscFrame := p.Threads[0].Frames[1]  // runtime: 0x1A0500000 + 0x40   = 0x1A0500040
	const (
		procRuntime = 0x100001234
		dscRuntime  = 0x1A0500040
		cacheBase   = 0x1A0000000
		dscOffset   = dscRuntime - cacheBase // 0x500040
	)

	tests := []struct {
		name     string
		cfg      Config
		frame    Frame
		wantHex  uint64
		wantName string
		wantNote bool // whether a slide note is expected
	}{
		{"proc/no-flags", Config{}, procFrame, procRuntime, "myapp", false},
		{"dsc/no-flags", Config{}, dscFrame, dscRuntime, "libsystem_kernel.dylib", false},
		{"proc/dsc-slide ignored", Config{DSCSlide: 0x180000000}, procFrame, procRuntime, "myapp", false},
		{"dsc/dsc-slide rebases", Config{DSCSlide: 0x180000000}, dscFrame, 0x180000000 + dscOffset, "libsystem_kernel.dylib", true},
		{"dsc/dsc-slide zero base", Config{DSCSlide: 0x1000}, dscFrame, 0x1000 + dscOffset, "libsystem_kernel.dylib", true},
		// --unslide is a no-op on 309 reports: they carry no per-frame slide.
		{"dsc/unslide no-op", Config{Unslid: true}, dscFrame, dscRuntime, "libsystem_kernel.dylib", false},
		{"proc/unslide no-op", Config{Unslid: true}, procFrame, procRuntime, "myapp", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			i := &Ips{Payload: p, Config: &cfg}
			addr, name, note := i.crashFrameAddr(tt.frame)
			if addr != tt.wantHex {
				t.Errorf("addr = %#x, want %#x", addr, tt.wantHex)
			}
			if name != tt.wantName {
				t.Errorf("name = %q, want %q", name, tt.wantName)
			}
			if (note != "") != tt.wantNote {
				t.Errorf("note = %q, wantNote = %v", note, tt.wantNote)
			}
		})
	}
}

func TestCrashFrameAddrImageIndexOutOfRange(t *testing.T) {
	// An out-of-range ImageIndex must not panic the render path (the helper owns
	// the only UsedImages access for 309 frames).
	i := &Ips{Payload: IPSPayload{}, Config: &Config{DSCSlide: 0x180000000}}
	addr, name, note := i.crashFrameAddr(Frame{ImageIndex: 5, ImageOffset: 0xabc})
	if addr != 0xabc || name != "image_5" || note != "" {
		t.Fatalf("out-of-range frame: got (%#x, %q, %q), want (0xabc, \"image_5\", \"\")", addr, name, note)
	}
}

func TestIPSPayloadTrialInfoFactorPackIdsArray(t *testing.T) {
	var payload IPSPayload
	data := []byte(`{
		"trialInfo": {
			"rollouts": [
				{
					"rolloutId": "66d35d7fe4d6bf7664f40ddf",
					"factorPackIds": ["68c1a34bd359577bbe8f2182"],
					"deploymentId": 240000067
				}
			]
		}
	}`)

	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	rollouts := payload.TrialInfo.Rollouts
	if len(rollouts) != 1 {
		t.Fatalf("expected 1 rollout, got %d", len(rollouts))
	}
	assertFactorPackIDs(t, rollouts[0].FactorPackIds, "68c1a34bd359577bbe8f2182")
}

func TestOpenIPSAcceptsTrialInfoFactorPackIdsArray(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ios26.ips")
	data := []byte(`{"bug_type":"309","os_version":"iPhone OS 26.0 (23A000)"}
{
	"modelCode": "iPhone17,1",
	"trialInfo": {
		"rollouts": [
			{
				"rolloutId": "66d35d7fe4d6bf7664f40ddf",
				"factorPackIds": ["68c1a34bd359577bbe8f2182"],
				"deploymentId": 240000067
			}
		]
	}
}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	ips, err := OpenIPS(path, &Config{})
	if err != nil {
		t.Fatalf("OpenIPS: %v", err)
	}

	rollouts := ips.Payload.TrialInfo.Rollouts
	if len(rollouts) != 1 {
		t.Fatalf("expected 1 rollout, got %d", len(rollouts))
	}
	assertFactorPackIDs(t, rollouts[0].FactorPackIds, "68c1a34bd359577bbe8f2182")
}

func TestIPSPayloadTrialInfoFactorPackIdsLegacyObject(t *testing.T) {
	var payload IPSPayload
	data := []byte(`{
		"trialInfo": {
			"rollouts": [
				{
					"rolloutId": "66d35d7fe4d6bf7664f40ddf",
					"factorPackIds": {},
					"deploymentId": 240000067
				}
			]
		}
	}`)

	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	rollouts := payload.TrialInfo.Rollouts
	if len(rollouts) != 1 {
		t.Fatalf("expected 1 rollout, got %d", len(rollouts))
	}
	assertFactorPackIDs(t, rollouts[0].FactorPackIds)
}

func TestFactorPackIdsRejectsInvalidShape(t *testing.T) {
	var factorPackIDs FactorPackIDs
	if err := json.Unmarshal([]byte(`"68c1a34bd359577bbe8f2182"`), &factorPackIDs); err == nil {
		t.Fatal("expected invalid scalar factorPackIds to fail")
	}
}

func assertFactorPackIDs(t *testing.T, got FactorPackIDs, want ...string) {
	t.Helper()

	if !slices.Equal(got, want) {
		t.Fatalf("unexpected factor pack IDs: got %#v, want %#v", got, want)
	}
}
