package disass

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-macho/types"
)

const chainedTestBase = uint64(0x100000000)

// chainedPointerFixture models an executable whose instruction operands are
// already VM addresses while its stored pointers are chained runtime offsets.
func chainedPointerFixture(t *testing.T, format fixupchains.DCPtrKind) []byte {
	t.Helper()
	write := func(dst *bytes.Buffer, value any) {
		t.Helper()
		if err := binary.Write(dst, binary.LittleEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	var starts, chains, header bytes.Buffer
	write(&starts, uint32(3))
	write(&starts, [3]uint32{0, 16, 0})
	write(&starts, fixupchains.DyldChainedStartsInSegment{
		Size: 24, PageSize: 0x1000, PointerFormat: format,
		SegmentOffset: 0x1000, PageCount: 1,
	})
	write(&starts, uint16(0x100))
	end := uint32(28 + starts.Len())
	write(&chains, fixupchains.DyldChainedFixupsHeader{
		StartsOffset: 28, ImportsOffset: end, SymbolsOffset: end,
		ImportsFormat: fixupchains.DC_IMPORT,
	})
	chains.Write(starts.Bytes())
	write(&header, types.FileHeader{
		Magic: types.Magic64, CPU: types.CPUArm64, Type: types.MH_EXECUTE,
		NCommands: 4, SizeCommands: 3*72 + 7*80 + 16,
	})
	segment := func(name string, offset uint64, nsect uint32) {
		s := types.Segment64{LoadCmd: types.LC_SEGMENT_64, Len: 72 + 80*nsect,
			Addr: chainedTestBase + offset, Memsz: 0x1000, Offset: offset, Filesz: 0x1000, Nsect: nsect}
		copy(s.Name[:], name)
		write(&header, s)
	}
	section := func(seg, name string, offset uint32, size uint64, flags types.SectionFlag) {
		s := types.Section64{Addr: chainedTestBase + uint64(offset), Size: size,
			Offset: offset, Align: 2, Flags: flags}
		if flags == types.SymbolStubs {
			s.Reserve2 = 12
		}
		copy(s.Name[:], name)
		copy(s.Seg[:], seg)
		write(&header, s)
	}
	segment("__TEXT", 0, 4)
	section("__TEXT", "__stubs", 0x400, 12, types.SymbolStubs)
	section("__TEXT", "__objc_stubs", 0x420, 12, 0)
	section("__TEXT", "__text", 0x460, 4, 0)
	section("__TEXT", "__objc_methname", 0x480, 0x30, types.CstringLiterals)
	segment("__DATA", 0x1000, 3)
	section("__DATA", "__objc_selrefs", 0x1108, 8, 0)
	section("__DATA", "__objc_classrefs", 0x1110, 8, 0)
	section("__DATA", "__objc_protorefs", 0x1118, 8, 0)
	segment("__LINKEDIT", 0x2000, 0)
	write(&header, types.LinkEditDataCmd{LoadCmd: types.LC_DYLD_CHAINED_FIXUPS,
		Len: 16, Offset: 0x2000, Size: uint32(chains.Len())})
	data := make([]byte, 0x3000)
	copy(data, header.Bytes())
	copy(data[0x2000:], chains.Bytes())
	copy(data[0x400:], encodeWords(0xb0000010, 0xf9408210, 0xd61f0200))
	copy(data[0x420:], encodeWords(0xb0000010, 0xf9408610, 0xd61f0200))
	copy(data[0x460:], encodeWords(0xd65f03c0))
	copy(data[0x480:], "perform:\x00")
	copy(data[0x490:], "ProbeClass\x00")
	copy(data[0x4a0:], "ProbeProtocol\x00")
	binary.LittleEndian.PutUint32(data[0x1380:], 2)  // RO_ROOT
	binary.LittleEndian.PutUint32(data[0x13d0:], 3)  // RO_ROOT | RO_META
	binary.LittleEndian.PutUint32(data[0x14c0:], 72) // protocol size
	pointers := []struct{ offset, target uint64 }{
		{0x1100, 0x460}, {0x1108, 0x480}, {0x1110, 0x1300}, {0x1118, 0x1480},
		{0x1300, 0x1340}, {0x1320, 0x1380}, {0x1360, 0x13d0},
		{0x1398, 0x490}, {0x13e8, 0x490}, {0x1488, 0x4a0},
	}
	stride, ok := fixupchains.Stride(format)
	if !ok {
		t.Fatalf("unsupported pointer format %v", format)
	}
	for i, ptr := range pointers {
		raw := ptr.target
		if i+1 < len(pointers) {
			raw |= (pointers[i+1].offset - ptr.offset) / stride << 51
		}
		binary.LittleEndian.PutUint64(data[ptr.offset:], raw)
	}
	return data
}

func TestParseStubsForMachOChainedOffsets(t *testing.T) {
	for _, format := range []fixupchains.DCPtrKind{
		fixupchains.DYLD_CHAINED_PTR_64_OFFSET,
		fixupchains.DYLD_CHAINED_PTR_ARM64E_USERLAND24,
	} {
		t.Run(format.String(), func(t *testing.T) {
			f, err := macho.NewFile(bytes.NewReader(chainedPointerFixture(t, format)))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			stubs, err := ParseStubsForMachO(f)
			if err != nil {
				t.Fatal(err)
			}
			if target := stubs[chainedTestBase+0x400]; len(stubs) != 1 || target != chainedTestBase+0x460 {
				t.Fatalf("unexpected stubs: %#v", stubs)
			}
		})
	}
}

func TestParseStubsForMachOFallbackReader(t *testing.T) {
	f, err := macho.NewFile(bytes.NewReader(chainedPointerFixture(t, fixupchains.DYLD_CHAINED_PTR_64_OFFSET)))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sec := f.Section("__TEXT", "__stubs")
	if sec == nil {
		t.Fatal("missing synthetic stubs section")
	}
	empty := bytes.NewReader(nil)
	sec.SetReaders(empty, io.NewSectionReader(empty, 0, 0))
	stubs, err := ParseStubsForMachO(f)
	if err != nil {
		t.Fatal(err)
	}
	if target := stubs[chainedTestBase+0x400]; len(stubs) != 1 || target != chainedTestBase+0x460 {
		t.Fatalf("unexpected fallback stubs: %#v", stubs)
	}
}

type stubDisass struct {
	data      []byte
	startAddr uint64
	asJSON    bool
}

func (s stubDisass) Triage() error                          { return nil }
func (s stubDisass) IsFunctionStart(uint64) (bool, string)  { return false, "" }
func (s stubDisass) IsLocation(uint64) bool                 { return false }
func (s stubDisass) IsBranchLocation(uint64) (bool, uint64) { return false, 0 }
func (s stubDisass) IsData(uint64) (bool, *AddrDetails)     { return false, nil }
func (s stubDisass) IsPointer(uint64) (bool, *AddrDetails)  { return false, nil }
func (s stubDisass) FindSymbol(uint64) (string, bool)       { return "", false }
func (s stubDisass) FindSwiftString(uint64) (string, bool)  { return "", false }
func (s stubDisass) GetCString(uint64) (string, error)      { return "", fmt.Errorf("no cstring") }
func (s stubDisass) Demangle() bool                         { return false }
func (s stubDisass) Quite() bool                            { return true }
func (s stubDisass) Color() bool                            { return false }
func (s stubDisass) AsJSON() bool                           { return s.asJSON }
func (s stubDisass) Data() []byte                           { return s.data }
func (s stubDisass) StartAddr() uint64                      { return s.startAddr }
func (s stubDisass) Middle() uint64                         { return 0 }
func (s stubDisass) ReadAddr(uint64) (uint64, error)        { return 0, fmt.Errorf("no pointer") }

func TestParseStubsASMADRPAndLDRStubDoesNotPanicOnTrailingBR(t *testing.T) {
	data := []byte{
		0x10, 0x00, 0x00, 0xd0, // adrp x16, ...
		0x10, 0x06, 0x40, 0xf9, // ldr  x16, [x16, #0x8]
		0x00, 0x02, 0x1f, 0xd6, // br   x16
	}

	stubs, err := ParseStubsASM(data, 0x100002d78, func(addr uint64) (uint64, error) {
		_ = addr
		return 0x100000ea0, nil
	})
	if err != nil {
		t.Fatalf("ParseStubsASM returned error: %v", err)
	}

	got, ok := stubs[0x100002d78]
	if !ok {
		t.Fatalf("expected stub entry at %#x, got none", uint64(0x100002d78))
	}
	if got != 0x100000ea0 {
		t.Fatalf("unexpected stub target: got %#x, want %#x", got, uint64(0x100000ea0))
	}
}

func TestParseStubsASMADRPAndAddBranchParsesStub(t *testing.T) {
	begin := uint64(0x100002d78)
	data := []byte{
		0x10, 0x00, 0x00, 0xd0, // adrp x16, ...
		0x10, 0x22, 0x00, 0x91, // add  x16, x16, #0x8
		0x00, 0x02, 0x1f, 0xd6, // br   x16
	}

	var decoder disassemble.Decoder
	var adrp disassemble.Inst
	if err := decoder.DecomposeInto(begin, binary.LittleEndian.Uint32(data[0:4]), &adrp); err != nil {
		t.Fatalf("failed to decompose adrp: %v", err)
	}
	want := adrp.Operands[1].Immediate + 0x8

	readPtrCalled := false
	stubs, err := ParseStubsASM(data, begin, func(addr uint64) (uint64, error) {
		readPtrCalled = true
		return 0, fmt.Errorf("unexpected readPtr call for ADRP+ADD+BR stub: %#x", addr)
	})
	if err != nil {
		t.Fatalf("ParseStubsASM returned error: %v", err)
	}
	if readPtrCalled {
		t.Fatalf("expected no readPtr calls for ADRP+ADD+BR stub")
	}

	got, ok := stubs[begin]
	if !ok {
		t.Fatalf("expected branch stub entry at %#x, got none", begin)
	}
	if got != want {
		t.Fatalf("unexpected branch stub target: got %#x, want %#x", got, want)
	}
}

func TestParseStubsASMArithmeticFarStubParsesTarget(t *testing.T) {
	// iOS 27 far-target arithmetic stub captured from dyld_shared_cache_arm64e
	// (build 24A5355q) at 0x188138000:
	//   adr  x16, 0x18803cc2c
	//   mov  x17, #0x9b7
	//   add  x16, x16, x17, lsl #0x15
	//   br   x16
	// target = 0x18803cc2c + (0x9b7 << 21) = 0x2bee3cc2c (no GOT load, no PAC).
	begin := uint64(0x188138000)
	data := []byte{
		0x70, 0x61, 0x82, 0x10, // adr  x16, 0x18803cc2c
		0xf1, 0x36, 0x81, 0xd2, // mov  x17, #0x9b7
		0x10, 0x56, 0x11, 0x8b, // add  x16, x16, x17, lsl #0x15
		0x00, 0x02, 0x1f, 0xd6, // br   x16
	}

	// Derive the expected target from an independent decode so the test verifies
	// the parser's arithmetic rather than a hand-computed constant.
	var decoder disassemble.Decoder
	var adr, mov, add disassemble.Inst
	if err := decoder.DecomposeInto(begin, binary.LittleEndian.Uint32(data[0:4]), &adr); err != nil {
		t.Fatalf("failed to decompose adr: %v", err)
	}
	if err := decoder.DecomposeInto(begin+4, binary.LittleEndian.Uint32(data[4:8]), &mov); err != nil {
		t.Fatalf("failed to decompose mov: %v", err)
	}
	if err := decoder.DecomposeInto(begin+8, binary.LittleEndian.Uint32(data[8:12]), &add); err != nil {
		t.Fatalf("failed to decompose add: %v", err)
	}
	want := adr.Operands[1].Immediate + (mov.Operands[1].Immediate << uint64(add.Operands[2].ShiftValue))

	stubs, err := ParseStubsASM(data, begin, func(addr uint64) (uint64, error) {
		return 0, fmt.Errorf("unexpected readPtr call for arithmetic stub: %#x", addr)
	})
	if err != nil {
		t.Fatalf("ParseStubsASM returned error: %v", err)
	}

	got, ok := stubs[begin]
	if !ok {
		t.Fatalf("expected arithmetic stub entry at %#x, got none", begin)
	}
	if got != want {
		t.Fatalf("unexpected arithmetic stub target: got %#x, want %#x", got, want)
	}
	if got != 0x2bee3cc2c {
		t.Fatalf("unexpected arithmetic stub target: got %#x, want %#x", got, uint64(0x2bee3cc2c))
	}
}

func TestParseStubsASMArithmeticStubMismatchedBranchRegisterIsIgnored(t *testing.T) {
	// Same arithmetic stub, but the final branch uses x17 instead of x16, so the
	// computed value never reaches the destination register: no stub should form.
	begin := uint64(0x188138000)
	data := []byte{
		0x70, 0x61, 0x82, 0x10, // adr  x16, 0x18803cc2c
		0xf1, 0x36, 0x81, 0xd2, // mov  x17, #0x9b7
		0x10, 0x56, 0x11, 0x8b, // add  x16, x16, x17, lsl #0x15
		0x20, 0x02, 0x1f, 0xd6, // br   x17 (mismatched destination)
	}

	stubs, err := ParseStubsASM(data, begin, func(addr uint64) (uint64, error) {
		return 0, fmt.Errorf("unexpected readPtr call: %#x", addr)
	})
	if err != nil {
		t.Fatalf("ParseStubsASM returned error: %v", err)
	}
	if len(stubs) != 0 {
		t.Fatalf("expected no stubs for mismatched branch register, got %v", stubs)
	}
}

func TestParseStubsASMArithmeticStubRejectsNonStubSequences(t *testing.T) {
	begin := uint64(0x188138000)
	adr := []byte{0x70, 0x61, 0x82, 0x10}    // adr x16, 0x18803cc2c
	movImm := []byte{0xf1, 0x36, 0x81, 0xd2} // mov x17, #0x9b7
	addLSL := []byte{0x10, 0x56, 0x11, 0x8b} // add x16, x16, x17, lsl #0x15
	brX16 := []byte{0x00, 0x02, 0x1f, 0xd6}  // br  x16

	concat := func(parts ...[]byte) []byte {
		var out []byte
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	decode := func(t *testing.T, b []byte) disassemble.Inst {
		t.Helper()
		var dec disassemble.Decoder
		var inst disassemble.Inst
		if err := dec.DecomposeInto(begin, binary.LittleEndian.Uint32(b), &inst); err != nil {
			t.Fatalf("failed to decode %#x: %v", b, err)
		}
		return inst
	}
	mustNoStub := func(t *testing.T, data []byte) {
		t.Helper()
		stubs, err := ParseStubsASM(data, begin, func(addr uint64) (uint64, error) {
			return 0, fmt.Errorf("unexpected readPtr call: %#x", addr)
		})
		if err != nil {
			t.Fatalf("ParseStubsASM returned error: %v", err)
		}
		if len(stubs) != 0 {
			t.Fatalf("expected no stub for non-stub sequence, got %v", stubs)
		}
	}

	t.Run("ConditionalBranchTerminator", func(t *testing.T) {
		// adr/mov/add followed by cbz (a compute-then-loop idiom), not a br tail-call.
		cbzX16 := []byte{0x10, 0x00, 0x00, 0xb4} // cbz x16, .
		if op := decode(t, cbzX16).Operation; op == disassemble.ARM64_BR {
			t.Fatalf("setup error: terminator decoded as BR, cannot test conditional branch")
		}
		mustNoStub(t, concat(adr, movImm, addLSL, cbzX16))
	})

	t.Run("RegisterMove", func(t *testing.T) {
		// mov x17, x18 (register move) instead of `mov x17, #imm`.
		movReg := []byte{0xf1, 0x03, 0x12, 0xaa} // mov x17, x18
		movInst := decode(t, movReg)
		if _, isReg := operandRegister(&movInst, 1); !isReg {
			t.Fatalf("setup error: mov source operand is not a register")
		}
		mustNoStub(t, concat(adr, movReg, addLSL, brX16))
	})

	t.Run("NonShiftedAdd", func(t *testing.T) {
		// add x16, x16, x17 with no LSL: operandLeftShift must reject it.
		addPlain := []byte{0x10, 0x02, 0x11, 0x8b} // add x16, x16, x17
		if decode(t, addPlain).Operands[2].ShiftValueUsed {
			t.Fatalf("setup error: add unexpectedly carries a shift")
		}
		mustNoStub(t, concat(adr, movImm, addPlain, brX16))
	})
}

func TestParseStubsASMMismatchedRegistersDoNotCreateStaleStubEntry(t *testing.T) {
	begin := uint64(0x100002d78)

	t.Run("ADRPAddLDRMismatch", func(t *testing.T) {
		data := []byte{
			0x11, 0x00, 0x00, 0xd0, // adrp x17, ...
			0x10, 0x22, 0x00, 0x91, // add  x16, x16, #0x8
			0x10, 0x06, 0x40, 0xf9, // ldr  x16, [x16, #0x8]
		}

		readPtrCalls := 0
		stubs, err := ParseStubsASM(data, begin, func(addr uint64) (uint64, error) {
			readPtrCalls++
			return 0x100000ea0, nil
		})
		if err != nil {
			t.Fatalf("ParseStubsASM returned error: %v", err)
		}
		if readPtrCalls != 0 {
			t.Fatalf("expected no readPtr calls on mismatched ADRP/ADD registers, got %d", readPtrCalls)
		}
		if len(stubs) != 0 {
			t.Fatalf("expected no stubs for mismatched ADRP/ADD registers, got %v", stubs)
		}
	})

	t.Run("ADRPAddBRMismatch", func(t *testing.T) {
		data := []byte{
			0x11, 0x00, 0x00, 0xd0, // adrp x17, ...
			0x10, 0x22, 0x00, 0x91, // add  x16, x16, #0x8
			0x00, 0x02, 0x1f, 0xd6, // br   x16
		}

		stubs, err := ParseStubsASM(data, begin, func(addr uint64) (uint64, error) {
			return 0x100000ea0, nil
		})
		if err != nil {
			t.Fatalf("ParseStubsASM returned error: %v", err)
		}
		if len(stubs) != 0 {
			t.Fatalf("expected no stubs for mismatched ADRP/ADD registers, got %v", stubs)
		}
	})
}

func TestDisassembleJSONPreservesDisassemblyString(t *testing.T) {
	out := Disassemble(stubDisass{
		data:      []byte{0x1f, 0x20, 0x03, 0xd5}, // nop
		startAddr: 0x1000,
		asJSON:    true,
	})

	var got []map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &got); err != nil {
		t.Fatalf("failed to unmarshal JSON disassembly output: %v\noutput=%s", err, out)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 instruction, got %d", len(got))
	}
	if addr, ok := got[0]["addr"].(float64); !ok || uint64(addr) != 0x1000 {
		t.Fatalf("unexpected instruction address payload: %#v", got[0]["addr"])
	}
	disassText, ok := got[0]["disass"].(string)
	if !ok {
		t.Fatalf("expected disass string in JSON payload, got %#v", got[0]["disass"])
	}
	if !strings.Contains(disassText, "nop") {
		t.Fatalf("expected JSON disassembly to contain nop, got %q", disassText)
	}
}

func TestMachoDisassContainsReturnsLowestReferenceDeterministically(t *testing.T) {
	tr := &Triage{Addresses: map[uint64]uint64{
		0x3000: 0x9000,
		0x1000: 0x9000,
		0x2000: 0x9000,
		0x4000: 0x8000,
	}}
	tr.indexReferences()
	d := MachoDisass{tr: tr}
	for range 64 {
		if ok, loc := d.Contains(0x9000); !ok || loc != 0x1000 {
			t.Fatalf("Contains(0x9000) = (%v, %#x), want (true, 0x1000)", ok, loc)
		}
	}
	if ok, loc := d.Contains(0x8000); !ok || loc != 0x4000 {
		t.Fatalf("Contains(0x8000) = (%v, %#x), want (true, 0x4000)", ok, loc)
	}
	if ok, loc := d.Contains(0x7000); ok || loc != 0 {
		t.Fatalf("Contains(0x7000) = (%v, %#x), want (false, 0)", ok, loc)
	}
	if ok, _ := (MachoDisass{}).Contains(0x9000); ok {
		t.Fatal("Contains on an untriaged disassembler must report false")
	}
}
