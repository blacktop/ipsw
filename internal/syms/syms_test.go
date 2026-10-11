package syms

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/pkg/dyld"
)

func writeComponentFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func componentMachoData(cpu types.CPU, subtype types.CPUSubtype, uuid byte) []byte {
	var data []byte
	// mach_header_64 followed by one LC_UUID command.
	for _, word := range []uint32{0xfeedfacf, uint32(cpu), uint32(subtype), 2, 1, 24, 0, 0, 0x1b, 24} {
		data = binary.LittleEndian.AppendUint32(data, word)
	}
	return append(data, uuid, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
}

func componentDscData(t *testing.T, platform types.Platform, uuid, symbolsUUID byte) []byte {
	t.Helper()
	var header dyld.CacheHeader
	copy(header.Magic[:], "dyld_v1arm64ex1")
	header.UUID[0], header.Platform = uuid, platform
	header.SymbolFileUUID[0] = symbolsUUID
	header.MappingOffset = uint32(binary.Size(header))
	header.ImagesOffset = header.MappingOffset
	header.DylibsTrieAddr = 0x1000
	header.CodeSignatureOffset = uint64(header.MappingOffset)
	header.CodeSignatureSize = 12
	var data bytes.Buffer
	if err := binary.Write(&data, binary.LittleEndian, header); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(&data, binary.BigEndian, []uint32{0xfade0cc0, 12, 0}); err != nil {
		t.Fatal(err)
	}
	return data.Bytes()
}

func TestComponentDSCDiscoveryCompletion(t *testing.T) {
	root := t.TempDir()
	driver := filepath.Join(root, "System/DriverKit/System/Library/dyld/dyld_shared_cache_arm64e")
	system := filepath.Join(root, "unrecognized/location/system.cache")
	writeComponentFile(t, driver, componentDscData(t, types.Platform_Driverkit, 1, 0))
	writeComponentFile(t, system, componentDscData(t, types.Platform_macOS, 2, 0))
	p := prepareTestComponent(t, "Cryptex1,SystemOS", "system.dmg", "", "dsc")
	var wire bytes.Buffer
	if err := p.scan(&wire, func(visit func(string, *scanImage) error) error {
		return p.scanMountedComponent(root, visit)
	}); err != nil {
		t.Fatal(err)
	}
	assertComponentCompletion(t, wire.Bytes(), 2, 2, 0, 0)
	if err := os.Remove(system); err != nil {
		t.Fatal(err)
	}
	wire.Reset()
	err := p.scan(&wire, func(visit func(string, *scanImage) error) error {
		return p.scanMountedComponent(root, visit)
	})
	if !errors.Is(err, dyld.ErrNoDscFound) || bytes.Contains(wire.Bytes(), []byte(`symbols_component_complete`)) {
		t.Fatalf("DriverKit-only component certified: err=%v wire=%s", err, &wire)
	}
	writeComponentFile(t, system, componentDscData(t, types.Platform_macOS, 2, 3))
	wire.Reset()
	err = p.scan(&wire, func(visit func(string, *scanImage) error) error {
		return p.scanMountedComponent(root, visit)
	})
	if !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), ".symbols") || bytes.Contains(wire.Bytes(), []byte(`symbols_component_complete`)) {
		t.Fatalf("missing DSC resource certified: err=%v wire=%s", err, &wire)
	}
}

func TestComponentDSCRequiredIdentities(t *testing.T) {
	uuid := types.UUID{1}
	for _, f := range []*dyld.File{
		nil,
		{},
		{UUID: uuid},
		{UUID: uuid, Headers: map[types.UUID]dyld.CacheHeader{uuid: {}}, Images: []*dyld.CacheImage{nil}},
		{UUID: uuid, Headers: map[types.UUID]dyld.CacheHeader{uuid: {}}, Images: []*dyld.CacheImage{{}}},
	} {
		if err := scanDSC(f, func(*scanImage) error { return nil }, nil, true); err == nil {
			t.Fatalf("accepted missing DSC/image identity: %+v", f)
		}
	}
	visits := 0
	f := &dyld.File{UUID: uuid, Headers: map[types.UUID]dyld.CacheHeader{uuid: {SharedRegionStart: 4096}}}
	if err := scanDSC(f, func(image *scanImage) error {
		visits++
		if image.Kind != "dsc" || image.DSCUUID != uuid.String() || image.SharedRegionStart != 4096 {
			t.Fatalf("unexpected DSC identity: %+v", image)
		}
		return nil
	}, nil, true); err != nil || visits != 1 {
		t.Fatalf("valid DSC visits=%d err=%v", visits, err)
	}
}

func TestComponentFilesystemReferenceSlice(t *testing.T) {
	arm := syntheticSlice(types.CPUArm64, types.CPUSubtypeArm64E, "", 1)
	intel := syntheticSlice(types.CPUAmd64, types.CPUSubtypeX8664All, "", 2)
	var got *scanImage
	if err := scanComponentMachoSlices("/tool", "SystemOS", []*macho.File{arm, intel}, func(image *scanImage) error {
		got = image
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Macho.UUID != intel.UUID().String() || got.Arch != "x86_64" {
		t.Fatalf("component did not select the last FAT slice: %+v", got)
	}
	noUUID := &macho.File{FileTOC: macho.FileTOC{FileHeader: types.FileHeader{CPU: types.CPUArm64}}}
	for _, slices := range [][]*macho.File{nil, {nil}, {noUUID}, {arm, noUUID}, {syntheticSlice(types.CPUArm64, 0, "", 0)}} {
		if err := scanComponentMachoSlices("/bad", "SystemOS", slices, func(*scanImage) error { return nil }); err == nil {
			t.Fatalf("missing selected identity accepted: %+v", slices)
		}
	}
	wantErr := errors.New("visitor failed")
	if err := scanComponentMachoSlices("/tool", "SystemOS", []*macho.File{arm}, func(*scanImage) error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("visitor failure suppressed: %v", err)
	}
}

func TestExtractScanKernelsRequiresIPSWMetadata(t *testing.T) {
	_, err := extractScanKernels("missing.ipsw", "", "", nil, &factsCollection{})
	if err == nil || !strings.Contains(err.Error(), "missing IPSW metadata") || !strings.Contains(err.Error(), "missing.ipsw") {
		t.Fatalf("expected missing IPSW metadata error, got %v", err)
	}
}

func seg(name string) *macho.Segment {
	return &macho.Segment{SegmentHeader: macho.SegmentHeader{Name: name, Addr: 0x1000, Filesz: 0x100}}
}

func file(segs ...*macho.Segment) *macho.File {
	var loads []macho.Load
	for _, s := range segs {
		loads = append(loads, s)
	}
	return &macho.File{FileTOC: macho.FileTOC{Loads: loads}}
}

// TestKextTextSegment is the regression for the UniversalMac com.apple.kec.Libm
// range bug: a stale __TEXT header alongside the relocated __TEXT_EXEC.
func TestKextTextSegment(t *testing.T) {
	staleText := seg("__TEXT")
	textExec := seg("__TEXT_EXEC")

	if got := kextTextSegment(file(staleText, textExec)); got != textExec {
		t.Fatalf("both segments present: got %+v, want __TEXT_EXEC", got)
	}
	if got := kextTextSegment(file(staleText)); got != staleText {
		t.Fatalf("__TEXT_EXEC absent: got %+v, want __TEXT fallback", got)
	}
	if got := kextTextSegment(file()); got != nil {
		t.Fatalf("no segments: got %+v, want nil", got)
	}
}
