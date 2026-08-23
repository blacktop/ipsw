package syms

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/internal/model"
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
