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

func TestCrashFrameAddrCompactImages(t *testing.T) {
	// 308 ExcUserFault ships compact usedImages (base/source/uuid, no name) and
	// no sharedCache block; source "S" frames must get a name and be DSC-aware.
	// image 0: source "S" whole cache at base 0x180000000 (== cache base)
	// image 1: source "C" library at base 0x180100000 (0x100000 into the cache)
	// image 2: source "P" process image, no name
	const payload = `{
		"procName": "MobileSMS",
		"usedImages": [
			{"base": 6442450944, "source": "S", "uuid": "90bbde82-938a-384b-8837-ed0c790bc5c9", "size": 4764545456},
			{"base": 6443499520, "source": "C", "uuid": "aa6fac5d-ceef-36e4-a309-950ecb55350d", "size": 262144},
			{"base": 4301897728, "source": "P", "uuid": "976fac5d-ceef-36e4-a309-950ecb55350d", "size": 11878400}
		],
		"threads": [{"triggered": true, "frames": [
			{"imageIndex": 0, "imageOffset": 752480},
			{"imageIndex": 1, "imageOffset": 1280},
			{"imageIndex": 2, "imageOffset": 100}
		]}]
	}`
	var p IPSPayload
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	i := &Ips{Payload: p, Config: &Config{}}

	// source "S" cache image with no name -> "dyld_shared_cache"
	addr, name, _ := i.crashFrameAddr(p.Threads[0].Frames[0])
	if name != "dyld_shared_cache" {
		t.Errorf("frame0 name = %q, want dyld_shared_cache", name)
	}
	if addr != 6442450944+752480 {
		t.Errorf("frame0 addr = %#x, want %#x", addr, uint64(6442450944+752480))
	}
	// source "C" library with no name -> "dyld_shared_cache" too
	if _, nameC, _ := i.crashFrameAddr(p.Threads[0].Frames[1]); nameC != "dyld_shared_cache" {
		t.Errorf("frame1 name = %q, want dyld_shared_cache", nameC)
	}
	// source "P" with no name -> procName
	if _, name2, _ := i.crashFrameAddr(p.Threads[0].Frames[2]); name2 != "MobileSMS" {
		t.Errorf("frame2 name = %q, want MobileSMS", name2)
	}

	// --dsc-slide rebases against the CACHE base (derived from the source-"S"
	// image), preserving each library's offset within the cache.
	i.Config.DSCSlide = 0x190000000
	// "S" frame: cache base 0x180000000 + offset -> slide + offset
	if a, _, slide := i.crashFrameAddr(p.Threads[0].Frames[0]); a != 0x190000000+752480 || slide == "" {
		t.Errorf("dsc-slide S frame = %#x %q, want %#x + note", a, slide, uint64(0x190000000+752480))
	}
	// "C" frame: lib base 0x180100000 + 1280 -> slide + (0x100000 + 1280); the
	// library's 0x100000 offset-in-cache must be preserved (the bug dropped it).
	if a, _, slide := i.crashFrameAddr(p.Threads[0].Frames[1]); a != 0x190000000+0x100000+1280 || slide == "" {
		t.Errorf("dsc-slide C frame = %#x %q, want %#x (offset-in-cache preserved)", a, slide, uint64(0x190000000+0x100000+1280))
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

// watchdogSample is a trimmed SystemWatchdogCrash (bug_type 409): a userspace
// watchdog (WindowServer) timed out. Its process/thread tables are nested under
// "stackshot" (not the payload top level) and there is no single panicked thread.
const watchdogSample = `{"name":"WindowServer","timestamp":"2026-06-23 22:58:51.00 -0600","os_version":"macOS 26.5.1 (25F80)","incident_id":"775BF885-132F-4CFC-BF2E-58A86445AA47","bug_type":"409","app_name":"WindowServer"}
{
  "build": "macOS 26.5.1 (25F80)",
  "modelCode": "Mac17,6",
  "bug_type": "409",
  "pid": 411,
  "procName": "WindowServer",
  "displayState": "OFF",
  "thermalPressureLevel": "ThermalPressureLevelNominal (0)",
  "termination": {
    "namespace": "WATCHDOG",
    "code": 1,
    "indicator": "monitoring timed out for service",
    "details": [
      "(1 monitored services unresponsive): checkin with service: WindowServer (0 induced crashes) returned not alive with context:",
      "is_alive_func returned unhealthy"
    ]
  },
  "reportNotes": [
    "task_read_for_pid(400) for resampling UUIDs failed with -1",
    "resampled 1547 of 10671 threads with truncated backtraces from 243 pids: 466,543",
    "2 unindexed user-stack frames from 1 pids: 28224",
    "This is a watchdog-triggered termination event, and not expected to be well-represented in the legacy crash format"
  ],
  "stackshot": {
    "processByPid": {
      "411": {
        "pid": 411,
        "procname": "WindowServer",
        "threadById": {
          "5336": {"id": 5336, "name": "com.apple.coreanimation.cursor.primary", "state": ["TH_WAIT"], "basePriority": 79, "schedPriority": 79, "user_usec": 7045119, "system_usec": 10638945, "userFrames": [[14, 4906036], [14, 4941760]]},
          "5348": {"id": 5348, "name": "com.apple.coreanimation.frameinfo.external-2", "state": ["TH_WAIT"], "basePriority": 79, "schedPriority": 79, "user_usec": 30352966, "system_usec": 17044713, "userFrames": [[14, 4906036]]}
        }
      },
      "1": {
        "pid": 1,
        "procname": "launchd",
        "threadById": {
          "100": {"id": 100, "state": ["TH_WAIT"], "userFrames": [[2, 1000]]}
        }
      }
    }
  }
}`

func writeWatchdogSample(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "WindowServer-watchdog.ips")
	if err := os.WriteFile(path, []byte(watchdogSample), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	return path
}

func TestOpenIPSWatchdog409(t *testing.T) {
	path := writeWatchdogSample(t)

	hdr, err := ParseHeader(path)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if hdr.BugType != "409" {
		t.Fatalf("BugType = %q, want 409", hdr.BugType)
	}
	if hdr.BugTypeDesc != "SystemWatchdogCrash" {
		t.Fatalf("BugTypeDesc = %q, want SystemWatchdogCrash", hdr.BugTypeDesc)
	}

	ips, err := OpenIPS(path, &Config{})
	if err != nil {
		t.Fatalf("OpenIPS: %v", err)
	}
	// the nested stackshot.processByPid must be promoted to the payload top level
	if len(ips.Payload.ProcessByPid) != 2 {
		t.Fatalf("ProcessByPid promoted count = %d, want 2", len(ips.Payload.ProcessByPid))
	}
	if ips.Payload.Termination.Namespace != "WATCHDOG" {
		t.Errorf("Termination.Namespace = %q, want WATCHDOG", ips.Payload.Termination.Namespace)
	}
	if len(ips.Payload.Termination.Details) != 2 {
		t.Errorf("Termination.Details len = %d, want 2", len(ips.Payload.Termination.Details))
	}
	if ips.Payload.DisplayState != "OFF" {
		t.Errorf("DisplayState = %q, want OFF", ips.Payload.DisplayState)
	}
}

func TestWatchdog409Render(t *testing.T) {
	prev := color.NoColor
	color.NoColor = true
	t.Cleanup(func() { color.NoColor = prev })

	ips, err := OpenIPS(writeWatchdogSample(t), &Config{})
	if err != nil {
		t.Fatalf("OpenIPS: %v", err)
	}
	out := ips.String()

	wantContains := []string{
		"SystemWatchdogCrash - Mac17,6",
		"Namespace:  WATCHDOG",
		"monitoring timed out for service",
		"checkin with service: WindowServer",
		"Display State  OFF",
		"Thermal Level  ThermalPressureLevelNominal (0)",
		"Process: WindowServer [411] (Panicked)",
		// the offending process shows ALL its threads even with no single
		// panicked thread flagged (panickedTID < 0)
		"com.apple.coreanimation.cursor.primary",
		"com.apple.coreanimation.frameinfo.external-2",
		// the lone signal note survives the noise filter
		"This is a watchdog-triggered termination event",
	}
	for _, w := range wantContains {
		if !strings.Contains(out, w) {
			t.Errorf("render missing %q\n--- output ---\n%s", w, out)
		}
	}

	wantAbsent := []string{
		"task_read_for_pid(", // stackshot resampling noise, filtered by default
		"resampled 1547",
		"unindexed",
		"launchd", // non-offending process hidden without --all
	}
	for _, w := range wantAbsent {
		if strings.Contains(out, w) {
			t.Errorf("render should not contain %q (default, non-verbose)\n--- output ---\n%s", w, out)
		}
	}
}

func TestWatchdog409VerboseKeepsNotes(t *testing.T) {
	prev := color.NoColor
	color.NoColor = true
	t.Cleanup(func() { color.NoColor = prev })

	ips, err := OpenIPS(writeWatchdogSample(t), &Config{Verbose: true})
	if err != nil {
		t.Fatalf("OpenIPS: %v", err)
	}
	out := ips.String()

	// --verbose keeps the full reportNotes, including the resampling diagnostics
	for _, w := range []string{"task_read_for_pid(400)", "resampled 1547"} {
		if !strings.Contains(out, w) {
			t.Errorf("verbose render missing %q\n--- output ---\n%s", w, out)
		}
	}
}

// watchdogNegPIDSample is the other real 409 shape: Apple emits a top-level
// pid of -1 and NO top-level build (the OS string lives only in the header's
// os_version). The renderer must identify the offending process by name so its
// threads still render, and fall back to os_version for the header banner.
const watchdogNegPIDSample = `{"name":"WindowServer","timestamp":"2026-06-23 22:58:51.00 -0600","os_version":"macOS 26.5.1 (25F80)","incident_id":"AABBCCDD-1122-3344-5566-778899AABBCC","bug_type":"409","app_name":"WindowServer"}
{
  "modelCode": "Mac17,6",
  "bug_type": "409",
  "pid": -1,
  "procName": "WindowServer",
  "termination": {
    "namespace": "WATCHDOG",
    "indicator": "monitoring timed out for service"
  },
  "stackshot": {
    "processByPid": {
      "411": {
        "pid": 411,
        "procname": "WindowServer",
        "threadById": {
          "5336": {"id": 5336, "name": "com.apple.main-thread", "state": ["TH_WAIT"], "userFrames": [[14, 4906036]]}
        }
      },
      "1": {
        "pid": 1,
        "procname": "launchd",
        "threadById": {
          "100": {"id": 100, "state": ["TH_WAIT"], "userFrames": [[2, 1000]]}
        }
      }
    }
  }
}`

func TestWatchdog409NegativePIDAndOSFallback(t *testing.T) {
	prev := color.NoColor
	color.NoColor = true
	t.Cleanup(func() { color.NoColor = prev })

	path := filepath.Join(t.TempDir(), "wd-negpid.ips")
	if err := os.WriteFile(path, []byte(watchdogNegPIDSample), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	ips, err := OpenIPS(path, &Config{})
	if err != nil {
		t.Fatalf("OpenIPS: %v", err)
	}
	out := ips.String()

	wantContains := []string{
		// pid -1 falls back to procName, so the offending process still renders
		"Process: WindowServer [411] (Panicked)",
		"com.apple.main-thread",
		// no top-level build → header falls back to the header os_version
		"SystemWatchdogCrash - Mac17,6 macOS 26.5.1 (25F80)",
	}
	for _, w := range wantContains {
		if !strings.Contains(out, w) {
			t.Errorf("render missing %q\n--- output ---\n%s", w, out)
		}
	}
	// non-offending process still hidden by default (no --all)
	if strings.Contains(out, "launchd") {
		t.Errorf("launchd should be hidden by default\n--- output ---\n%s", out)
	}
}
