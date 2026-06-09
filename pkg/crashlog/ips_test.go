package crashlog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

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
