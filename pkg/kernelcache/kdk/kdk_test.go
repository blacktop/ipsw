package kdk

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

func TestFindUsagesOfRegisterScansPastFirstInstruction(t *testing.T) {
	var data bytes.Buffer
	for _, instruction := range []uint32{
		0xb94a512a, // ldr w10, [x9, #0xa50]
		0x2a080148, // orr w8, w10, w8
		0xb90a5128, // str w8, [x9, #0xa50]
		0x91000009, // add x9, x0, #0; overwrites the tracked register
	} {
		if err := binary.Write(&data, binary.LittleEndian, instruction); err != nil {
			t.Fatal(err)
		}
	}

	got := (&recovery{}).findUsagesOfRegister(
		bytes.NewReader(data.Bytes()),
		nil,
		0xc284,
		9,
		0xfffffe000aad2000,
		make(map[uint64]bool),
		make(map[uint64][]uint8),
	)
	for _, address := range []uint64{0xc284, 0xc28c} {
		if target := got[address]; target != 0xfffffe000aad2a50 {
			t.Fatalf("target at %#x = %#x, want %#x", address, target, uint64(0xfffffe000aad2a50))
		}
	}
	if len(got) != 2 {
		t.Fatalf("found %d register uses, want 2", len(got))
	}
}

func TestAddressInFunctionExcludesFollowingFunction(t *testing.T) {
	function := types.Function{StartAddr: 0x1000, EndAddr: 0x1100}
	for _, address := range []uint64{0x1000, 0x1080, 0x10fc} {
		if !addressInFunction(address, function) {
			t.Fatalf("address %#x should be inside function", address)
		}
	}
	for _, address := range []uint64{0x0ffc, 0x1100, 0x1200} {
		if addressInFunction(address, function) {
			t.Fatalf("address %#x should be outside function", address)
		}
	}
}

func TestRangesOverlapFindsSegmentContainedInPage(t *testing.T) {
	const pageStart = uint64(0xfffffe000aad0000)
	if !rangesOverlap(pageStart, pageStart+0x1000, pageStart+0x488, pageStart+0x988) {
		t.Fatal("segment contained within ADRP target page was not detected")
	}
	if rangesOverlap(pageStart, pageStart+0x1000, pageStart+0x1000, pageStart+0x1200) {
		t.Fatal("adjacent segment was reported as overlapping")
	}
}

func TestExtractKextInfoMatchesIdentifierExactly(t *testing.T) {
	infos := []bundleInfo{
		{"CFBundleIdentifier": "com.apple.driver.usb.AppleUSBVHCICommon"},
		{"CFBundleIdentifier": "com.apple.driver.usb.AppleUSBVHCI"},
	}
	info, err := extractKextInfo(infos, "com.apple.driver.usb.AppleUSBVHCI")
	if err != nil {
		t.Fatal(err)
	}
	if got := info["CFBundleIdentifier"]; got != "com.apple.driver.usb.AppleUSBVHCI" {
		t.Fatalf("CFBundleIdentifier = %v", got)
	}
}

func TestStandaloneKextInfoDropsCollectionKeys(t *testing.T) {
	info := bundleInfo{
		"CFBundleIdentifier":             "com.apple.filesystems.webdav",
		"CFBundleExecutable":             "webdav_fs",
		"CFBundleNumericVersion":         uint64(1),
		"OSBundleUUID":                   []byte{1},
		"_InfoPlistDigest":               []byte{2},
		"_PrelinkExecutableRelativePath": "Contents/MacOS/webdav_fs",
		"_PrelinkKmodInfo":               uint64(3),
	}
	got := standaloneKextInfo(info)
	if len(got) != 2 || got["CFBundleExecutable"] != "webdav_fs" {
		t.Fatalf("standalone info = %v", got)
	}
	if len(info) != 7 {
		t.Fatal("standaloneKextInfo modified its input")
	}
}

func TestKextBundleLayoutFollowsPrelinkPaths(t *testing.T) {
	cases := []struct {
		info               bundleInfo
		bundle, plist, exe string
	}{
		{bundleInfo{"_PrelinkBundlePath": "/System/Library/Extensions/AppleHIDMouse.kext/Contents/PlugIns/AppleUSBHIDMouse.kext", "_PrelinkExecutableRelativePath": "Contents/MacOS/AppleUSBHIDMouse"},
			"E/AppleHIDMouse.kext/Contents/PlugIns/AppleUSBHIDMouse.kext", "E/AppleHIDMouse.kext/Contents/PlugIns/AppleUSBHIDMouse.kext/Contents/Info.plist", "E/AppleHIDMouse.kext/Contents/PlugIns/AppleUSBHIDMouse.kext/Contents/MacOS/AppleUSBHIDMouse"},
		{bundleInfo{"_PrelinkBundlePath": "/System/Library/Extensions/IOGraphicsFamily.kext", "_PrelinkExecutableRelativePath": "IOGraphicsFamily"},
			"E/IOGraphicsFamily.kext", "E/IOGraphicsFamily.kext/Info.plist", "E/IOGraphicsFamily.kext/IOGraphicsFamily"},
		{bundleInfo{"_PrelinkBundlePath": "/System/Library/Extensions/AppleStorageDrivers.kext", "DTPlatformName": "macosx"},
			"E/AppleStorageDrivers.kext", "E/AppleStorageDrivers.kext/Contents/Info.plist", ""},
		{bundleInfo{"CFBundleExecutable": "foo"}, "E/com.example.foo.kext", "E/com.example.foo.kext/Info.plist", "E/com.example.foo.kext/foo"},
	}
	for _, c := range cases {
		bundle, plist, exe, err := kextBundleLayout("E", "com.example.foo", c.info)
		if err != nil {
			t.Fatal(err)
		}
		if bundle != c.bundle || plist != c.plist || exe != c.exe {
			t.Errorf("layout = %q %q %q, want %q %q %q", bundle, plist, exe, c.bundle, c.plist, c.exe)
		}
	}
}

func TestLoadSymbolMapAcceptsNameLists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "symbols.json")
	if err := os.WriteFile(path, []byte(`{"18446741874686296064":"_a","0x10":["_b","_c"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	symbols, err := LoadSymbolMap(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := symbols[0xfffffe0000000000]; len(got) != 1 || got[0] != "_a" {
		t.Errorf("single name = %v", got)
	}
	if got := symbols[0x10]; len(got) != 2 || got[0] != "_b" || got[1] != "_c" {
		t.Errorf("name list = %v", got)
	}
}

func TestInstructionWritesRegisterIgnoresSIMDDestinations(t *testing.T) {
	for _, tc := range []struct {
		insn   uint32
		reg    uint8
		writes bool
		text   string
	}{
		{0x6e042087, 7, false, "ext v7.16b, v4.16b, v4.16b, #4"},
		{0x0f08a483, 3, false, "sxtl v3.8h, v4.8b"},
		{0x3dc158f3, 19, false, "ldr q19, [x7, #0x560]"},
		{0x9e660000, 0, true, "fmov x0, d0"},
		{0x0e0c3c00, 0, true, "umov w0, v0.s[1]"},
		{0x1e202000, 0, false, "fcmp s0, s0"},
		{0x91000009, 9, true, "add x9, x0, #0"},
	} {
		if got := instructionWritesRegister(tc.insn, tc.reg); got != tc.writes {
			t.Errorf("%s: writes x%d = %v, want %v", tc.text, tc.reg, got, tc.writes)
		}
	}
}

func TestAuthenticatedBranchClassification(t *testing.T) {
	for _, tc := range []struct {
		insn       uint32
		jump, call bool
		text       string
	}{
		{0xd71f0851, true, false, "braa x2, x17"},
		{0xd61f081f, true, false, "braaz x0"},
		{0xd71f0c00, true, false, "brab x0, x0"},
		{0xd61f0000, false, false, "br x0"},
		{0xd73f0911, false, true, "blraa x8, x17"},
		{0xd63f081f, false, true, "blraaz x0"},
		{0xd63f0100, false, false, "blr x8"},
		{0xd65f0bff, false, false, "retaa"},
	} {
		if got := isAuthenticatedJump(tc.insn); got != tc.jump {
			t.Errorf("%s: isAuthenticatedJump = %v", tc.text, got)
		}
		if got := isAuthenticatedCall(tc.insn); got != tc.call {
			t.Errorf("%s: isAuthenticatedCall = %v", tc.text, got)
		}
	}
}

func TestBranchTarget(t *testing.T) {
	for _, tc := range []struct {
		insn       uint32
		pc, target uint64
	}{
		{0x17FFFFFE, 0x1000, 0xFF8},  // b .-8
		{0x94000040, 0x1000, 0x1100}, // bl .+0x100
		{0x54000100, 0x1000, 0x1020}, // b.eq .+0x20
		{0xB4FFFFE0, 0x1000, 0xFFC},  // cbz x0, .-4
		{0x36000040, 0x1000, 0x1008}, // tbz w0, #0, .+8
	} {
		if got, ok := branchTarget(tc.insn, tc.pc); !ok || got != tc.target {
			t.Errorf("branchTarget(%#08x) = %#x, %v; want %#x", tc.insn, got, ok, tc.target)
		}
	}
	if _, ok := branchTarget(0x91004100, 0x1000); ok {
		t.Error("an ADD is not a branch")
	}
}

func TestDecodeUnwindHeaderRejectsTruncatedData(t *testing.T) {
	if _, err := decodeUnwindHeader(make([]byte, 27)); err == nil {
		t.Error("expected an error for a truncated __unwind_info header")
	}
}

// A jump table's cases may lie before the ADR: their offsets are negative.
func TestHandleBrFollowsNegativeJumpTableOffsets(t *testing.T) {
	const base = 0x4000
	var data bytes.Buffer
	for _, insn := range []uint32{
		0x91004100, // 0x00 add   x0, x8, #0x10 (case 0, uses the tracked x8)
		0xD65F03C0, // 0x04 ret
		0x7100053F, // 0x08 cmp   w9, #1
		0xD503201F, // 0x0c nop   (csneg)
		0x9000000A, // 0x10 adrp  x10, base
		0x9100C14A, // 0x14 add   x10, x10, #0x30
		0xB8A9794B, // 0x18 ldrsw x11, [x10, x9, lsl #2]
		0x1000000C, // 0x1c adr   x12, .
		0x8B0B018D, // 0x20 add   x13, x12, x11
		0xD61F01A0, // 0x24 br    x13
		0xD503201F, // 0x28 nop
		0xD503201F, // 0x2c nop
		0xFFFFFFE4, // 0x30 jump table: case 0 at 0x00 - 0x1c
	} {
		binary.Write(&data, binary.LittleEndian, insn)
	}
	r := bytes.NewReader(data.Bytes())
	r.Seek(0x28, io.SeekStart) // just after the BR
	result := make(map[uint64]uint64)
	rc := &recovery{}
	rc.handleBr(0xD61F01A0, r,
		func(pos int64) uint64 { return base + uint64(pos) },
		0xfffffe0000100000,
		func(addr uint64) int64 { return int64(addr - base) },
		result, nil, 8, make(map[uint64]bool), make(map[uint64][]uint8))
	if got := result[base]; got != 0xfffffe0000100010 {
		t.Errorf("case reference = %#x, want 0xfffffe0000100010 (all: %v)", got, result)
	}
}

func TestKextBundleLayoutRejectsEscapingPaths(t *testing.T) {
	for _, info := range []bundleInfo{
		{"_PrelinkBundlePath": "/System/Library/Extensions/../../../../etc/Foo.kext"},
		{"_PrelinkExecutableRelativePath": "../../../Foo"},
	} {
		if _, _, _, err := kextBundleLayout(t.TempDir(), "com.example.foo", info); err == nil {
			t.Errorf("expected an error for %v", info)
		}
	}
}

func TestPseudoExtensionMachO(t *testing.T) {
	uuid := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	m, err := macho.NewFile(bytes.NewReader(pseudoExtensionMachO(uuid, []string{"_IOLog", "_bzero"})))
	if err != nil {
		t.Fatal(err)
	}
	if m.Type != types.MH_KEXT_BUNDLE {
		t.Errorf("file type = %v, want MH_KEXT_BUNDLE", m.Type)
	}
	if got := m.UUID(); got == nil || !bytes.Equal(got.UUID[:], uuid) {
		t.Errorf("UUID = %v, want %x", got, uuid)
	}
	var names []string
	for _, sym := range m.Symtab.Syms {
		if !sym.Type.IsUndefinedSym() {
			t.Errorf("%s is not undefined", sym.Name)
		}
		names = append(names, sym.Name)
	}
	if !slices.Equal(names, []string{"_IOLog", "_bzero"}) {
		t.Errorf("symbols = %v", names)
	}
}
