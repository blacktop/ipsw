package xref

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/blacktop/arm64-cgo/disassemble"
)

type mockMemory struct {
	ptrs map[uint64]uint64
}

func (m mockMemory) ReadPointer(addr uint64) (uint64, error) {
	ptr, ok := m.ptrs[addr]
	if !ok {
		return 0, errNoPointer(addr)
	}
	return ptr, nil
}

type errNoPointer uint64

func (e errNoPointer) Error() string {
	return "no pointer"
}

func TestScanFunctionMatchesDirectBranchTargets(t *testing.T) {
	base := uint64(0x100000000)
	target := uint64(0x100002000)
	data := words(
		encBL(base, target),
		encB(base+4, target),
	)

	results := ScanFunction(data, base, Options{
		Targets: NewTargetSet(target),
		Mode:    ModeCalls,
	})

	if len(results) != 2 {
		t.Fatalf("results=%d, want 2", len(results))
	}
	if results[0].Address != base || results[0].Target != target {
		t.Fatalf("unexpected first result: %#v", results[0])
	}
	if results[1].Address != base+4 || results[1].Target != target {
		t.Fatalf("unexpected second result: %#v", results[1])
	}
}

func TestScanFunctionResolvesBLRThroughLoadedPointer(t *testing.T) {
	base := uint64(0x100000000)
	slot := uint64(0x100003040)
	target := uint64(0x100005000)
	data := words(
		encADRP(16, base, slot),
		encADDImm(16, 16, slot&0xfff),
		encLDRUnsigned(16, 16, 0),
		encBLR(16),
	)

	results := ScanFunction(data, base, Options{
		Targets:         NewTargetSet(target),
		Reader:          mockMemory{ptrs: map[uint64]uint64{slot: target}},
		Mode:            ModeCalls,
		ResolveIndirect: true,
	})

	if len(results) != 1 {
		t.Fatalf("results=%d, want 1", len(results))
	}
	if results[0].Address != base+12 || results[0].Target != target {
		t.Fatalf("unexpected result: %#v", results[0])
	}
}

func TestScanFunctionDoesNotResolveRegisterOffsetLoadAsZeroOffset(t *testing.T) {
	base := uint64(0x100000000)
	slot := uint64(0x100003040)
	target := uint64(0x100005000)
	data := words(
		encADRP(16, base, slot),
		encADDImm(16, 16, slot&0xfff),
		encLDRRegisterOffset(16, 16, 17),
		encBLR(16),
	)

	results := ScanFunction(data, base, Options{
		Targets:         NewTargetSet(target),
		Reader:          mockMemory{ptrs: map[uint64]uint64{slot: target}},
		Mode:            ModeCalls,
		ResolveIndirect: true,
	})

	if len(results) != 0 {
		t.Fatalf("results=%d, want 0 for register-offset load", len(results))
	}
}

func TestScanFunctionPostIndexLoadReadsOriginalBase(t *testing.T) {
	base := uint64(0x100000000)
	slot := uint64(0x100003040)
	target := uint64(0x100005000)
	other := uint64(0x100006000)
	data := words(
		encADRP(16, base, slot),
		encADDImm(16, 16, slot&0xfff),
		encLDRPostIndex(17, 16, 8),
		encBLR(17),
	)

	results := ScanFunction(data, base, Options{
		Targets: NewTargetSet(target, other),
		Reader: mockMemory{ptrs: map[uint64]uint64{
			slot:     target,
			slot + 8: other,
		}},
		Mode:            ModeCalls,
		ResolveIndirect: true,
	})

	if len(results) != 1 {
		t.Fatalf("results=%d, want 1", len(results))
	}
	if results[0].Target != target {
		t.Fatalf("target=%#x, want original-base target %#x", results[0].Target, target)
	}
}

func TestScanFunctionPostIndexLoadUpdatesBase(t *testing.T) {
	base := uint64(0x100000000)
	slot := uint64(0x100003040)
	target := slot + 8
	data := words(
		encADRP(16, base, slot),
		encADDImm(16, 16, slot&0xfff),
		encLDRPostIndex(17, 16, 8),
		encBLR(16),
	)

	results := ScanFunction(data, base, Options{
		Targets:         NewTargetSet(target),
		Mode:            ModeCalls,
		ResolveIndirect: true,
	})

	if len(results) != 1 {
		t.Fatalf("results=%d, want 1", len(results))
	}
	if results[0].Target != target {
		t.Fatalf("target=%#x, want writeback target %#x", results[0].Target, target)
	}
}

func TestScanFunctionResolvesBLRThroughLDURPointer(t *testing.T) {
	base := uint64(0x100000000)
	slot := uint64(0x100003040)
	target := uint64(0x100005000)
	data := words(
		encADRP(16, base, slot),
		encADDImm(16, 16, slot&0xfff),
		encLDUR(16, 16, -8),
		encBLR(16),
	)

	results := ScanFunction(data, base, Options{
		Targets:         NewTargetSet(target),
		Reader:          mockMemory{ptrs: map[uint64]uint64{slot - 8: target}},
		Mode:            ModeCalls,
		ResolveIndirect: true,
	})

	if len(results) != 1 {
		t.Fatalf("results=%d, want 1", len(results))
	}
	if results[0].Target != target {
		t.Fatalf("target=%#x, want LDUR target %#x", results[0].Target, target)
	}
}

func TestScanFunctionResolvesAuthBranchVariant(t *testing.T) {
	base := uint64(0x100000000)
	target := uint64(0x100005000)
	data := words(
		encADRP(0, base, target),
		encADDImm(0, 0, target&0xfff),
		encBLRAAZ(0),
	)

	results := ScanFunction(data, base, Options{
		Targets:         NewTargetSet(target),
		Mode:            ModeCalls,
		ResolveIndirect: true,
	})

	if len(results) != 1 {
		t.Fatalf("results=%d, want 1", len(results))
	}
	if results[0].Address != base+8 || results[0].Target != target {
		t.Fatalf("unexpected auth branch result: %#v", results[0])
	}
}

func TestScanFunctionResolvesBKeyAuthBranchReference(t *testing.T) {
	base := uint64(0x100000000)
	target := uint64(0x100005000)
	data := words(
		encADRP(16, base, target),
		encADDImm(16, 16, target&0xfff),
		encBRABZ(16),
	)

	results := ScanFunction(data, base, Options{
		Targets:         NewTargetSet(target),
		Mode:            ModeReferences,
		ResolveIndirect: true,
	})

	if len(results) != 2 {
		t.Fatalf("results=%d, want 2", len(results))
	}
	if results[1].Address != base+8 || results[1].Target != target {
		t.Fatalf("unexpected auth branch reference result: %#v", results[1])
	}
}

func TestScanFunctionResolvesMOVZMOVKTarget(t *testing.T) {
	base := uint64(0x100000000)
	target := uint64(0x100005000)
	data := words(
		encMOVZ(16, 0x5000, 0),
		encMOVK(16, 0x1, 32),
		encBLR(16),
	)

	results := ScanFunction(data, base, Options{
		Targets:         NewTargetSet(target),
		Mode:            ModeCalls,
		ResolveIndirect: true,
	})

	if len(results) != 1 {
		t.Fatalf("results=%d, want 1", len(results))
	}
	if results[0].Target != target {
		t.Fatalf("target=%#x, want %#x", results[0].Target, target)
	}
}

func TestScanFunctionClearsVolatileRegistersAcrossCalls(t *testing.T) {
	base := uint64(0x100000000)
	target := uint64(0x100005000)
	other := uint64(0x100006000)
	data := words(
		encADRP(16, base, target),
		encADDImm(16, 16, target&0xfff),
		encBL(base+8, other),
		encBLR(16),
	)

	results := ScanFunction(data, base, Options{
		Targets:         NewTargetSet(target),
		Mode:            ModeCalls,
		ResolveIndirect: true,
	})

	if len(results) != 0 {
		t.Fatalf("results=%d, want 0 after volatile register clobber", len(results))
	}
}

func TestScanFunctionClearsBothLoadPairDestinations(t *testing.T) {
	base := uint64(0x100000000)
	target := uint64(0x100005000)
	instrs := Decode(words(
		encADRP(1, base, target),
		encADDImm(1, 1, target&0xfff),
	), base)
	instrs = append(instrs,
		Instruction{Inst: disassemble.Inst{
			Address:   base + 8,
			Operation: disassemble.ARM64_LDP,
			NumOps:    3,
			Operands: [disassemble.MAX_OPERANDS]disassemble.Op{
				regOp(disassemble.REG_X0),
				regOp(disassemble.REG_X1),
				regOp(disassemble.REG_SP),
			},
		}},
		Instruction{Inst: disassemble.Inst{
			Address:   base + 12,
			Operation: disassemble.ARM64_BLR,
			NumOps:    1,
			Operands: [disassemble.MAX_OPERANDS]disassemble.Op{
				regOp(disassemble.REG_X1),
			},
		}},
	)

	results := ScanInstructions(instrs, Options{
		Targets:         NewTargetSet(target),
		Mode:            ModeCalls,
		ResolveIndirect: true,
	})
	if len(results) != 0 {
		t.Fatalf("results=%d, want 0 after LDP clobbers second destination", len(results))
	}
}

func TestScanFunctionUsesBoundedStateWindow(t *testing.T) {
	base := uint64(0x100000000)
	target := uint64(0x100005000)
	wordsIn := []uint32{
		encADRP(16, base, target),
		encADDImm(16, 16, target&0xfff),
	}
	for range DefaultMaxInstructions {
		wordsIn = append(wordsIn, encNOP())
	}
	wordsIn = append(wordsIn, encBLR(16))
	data := words(wordsIn...)

	results := ScanFunction(data, base, Options{
		Targets:         NewTargetSet(target),
		Mode:            ModeCalls,
		ResolveIndirect: true,
	})
	if len(results) != 0 {
		t.Fatalf("results=%d, want 0 with default state window", len(results))
	}

	results = ScanFunction(data, base, Options{
		Targets:         NewTargetSet(target),
		Mode:            ModeCalls,
		ResolveIndirect: true,
		MaxInstructions: DefaultMaxInstructions + 2,
	})
	if len(results) != 1 {
		t.Fatalf("results=%d, want 1 with wider state window", len(results))
	}
}

func TestScanFunctionCallModeIgnoresNonCallReferences(t *testing.T) {
	base := uint64(0x100000000)
	ref := uint64(0x100004040)
	data := words(
		encADRP(1, base, ref),
		encADDImm(1, 1, ref&0xfff),
	)

	results := ScanFunction(data, base, Options{
		Targets: NewTargetSet(ref),
		Mode:    ModeCalls,
	})
	if len(results) != 0 {
		t.Fatalf("call-mode results=%d, want 0", len(results))
	}

	results = ScanFunction(data, base, Options{
		Targets: NewTargetSet(ref),
		Mode:    ModeReferences,
	})
	if len(results) != 1 {
		t.Fatalf("reference-mode results=%d, want 1", len(results))
	}
}

func TestDirectBranchTargetSupportsNegativeOffset(t *testing.T) {
	base := uint64(0x100000000)
	target, ok := DirectBranchTarget(encB(base+4, base), base+4)
	if !ok {
		t.Fatal("negative direct branch did not decode")
	}
	if target != base {
		t.Fatalf("target=%#x, want %#x", target, base)
	}
}

func TestStubPointerSlotsFromInstructionsADRPAndLDR(t *testing.T) {
	begin := uint64(0x100002d78)
	data := []byte{
		0x10, 0x00, 0x00, 0xd0,
		0x10, 0x06, 0x40, 0xf9,
		0x00, 0x02, 0x1f, 0xd6,
	}

	instrs := Decode(data, begin)
	want := instrs[0].Operands[1].Immediate + 0x8
	slots := StubPointerSlotsFromInstructions(instrs)
	if got := slots[begin]; got != want {
		t.Fatalf("unexpected slot: got %#x, want %#x", got, want)
	}
}

func TestStubPointerSlotsFromInstructionsADRPAddAndLDR(t *testing.T) {
	begin := uint64(0x100002d78)
	data := []byte{
		0x10, 0x00, 0x00, 0xd0,
		0x10, 0x22, 0x00, 0x91,
		0x10, 0x06, 0x40, 0xf9,
		0x00, 0x02, 0x1f, 0xd6,
	}

	instrs := Decode(data, begin)
	want := instrs[0].Operands[1].Immediate + 0x10
	slots := StubPointerSlotsFromInstructions(instrs)
	if got := slots[begin]; got != want {
		t.Fatalf("unexpected slot: got %#x, want %#x", got, want)
	}
}

func TestStubPointerSlotsFromInstructionsMismatchedRegisters(t *testing.T) {
	begin := uint64(0x100002d78)
	data := []byte{
		0x11, 0x00, 0x00, 0xd0,
		0x10, 0x22, 0x00, 0x91,
		0x10, 0x06, 0x40, 0xf9,
	}

	slots := StubPointerSlotsFromInstructions(Decode(data, begin))
	if len(slots) != 0 {
		t.Fatalf("expected no slots, got %v", slots)
	}
}

func TestStubPointerSlotsFromInstructionsRejectsRegisterOffsetLoad(t *testing.T) {
	begin := uint64(0x100002d78)
	data := words(
		encADRP(16, begin, 0x100004000),
		encLDRRegisterOffset(16, 16, 17),
	)

	slots := StubPointerSlotsFromInstructions(Decode(data, begin))
	if len(slots) != 0 {
		t.Fatalf("expected no slots for register-offset load, got %v", slots)
	}
}

func words(ws ...uint32) []byte {
	var buf bytes.Buffer
	for _, w := range ws {
		_ = binary.Write(&buf, binary.LittleEndian, w)
	}
	return buf.Bytes()
}

func encADRP(rd int, pc, target uint64) uint32 {
	pcPage := pc &^ 0xfff
	targetPage := target &^ 0xfff
	pages := int64(targetPage-pcPage) / 0x1000
	imm := uint32(uint64(pages) & ((1 << 21) - 1))
	immlo := imm & 0x3
	immhi := (imm >> 2) & 0x7ffff
	return 0x90000000 | (immlo << 29) | (immhi << 5) | uint32(rd)
}

func encADDImm(rd, rn int, imm uint64) uint32 {
	return 0x91000000 | (uint32(imm&0xfff) << 10) | (uint32(rn) << 5) | uint32(rd)
}

func encMOVZ(rd int, imm uint16, shift uint) uint32 {
	return 0xd2800000 | ((uint32(shift/16) & 0x3) << 21) | (uint32(imm) << 5) | uint32(rd)
}

func encMOVK(rd int, imm uint16, shift uint) uint32 {
	return 0xf2800000 | ((uint32(shift/16) & 0x3) << 21) | (uint32(imm) << 5) | uint32(rd)
}

func encLDRUnsigned(rt, rn int, imm uint64) uint32 {
	return 0xf9400000 | (uint32((imm/8)&0xfff) << 10) | (uint32(rn) << 5) | uint32(rt)
}

func encLDRRegisterOffset(rt, rn, rm int) uint32 {
	return 0xf8606800 | (uint32(rm) << 16) | (uint32(rn) << 5) | uint32(rt)
}

func encLDRPostIndex(rt, rn int, imm int64) uint32 {
	return 0xf8400400 | ((uint32(uint64(imm) & 0x1ff)) << 12) | (uint32(rn) << 5) | uint32(rt)
}

func encLDUR(rt, rn int, imm int64) uint32 {
	return 0xf8400000 | ((uint32(uint64(imm) & 0x1ff)) << 12) | (uint32(rn) << 5) | uint32(rt)
}

func encBL(pc, target uint64) uint32 {
	off := int64(target-pc) / 4
	return 0x94000000 | (uint32(uint64(off)) & 0x03ffffff)
}

func encB(pc, target uint64) uint32 {
	off := int64(target-pc) / 4
	return 0x14000000 | (uint32(uint64(off)) & 0x03ffffff)
}

func encBLR(rn int) uint32 {
	return 0xd63f0000 | (uint32(rn) << 5)
}

func encBLRAAZ(rn int) uint32 {
	return 0xd63f081f | (uint32(rn) << 5)
}

func encBRABZ(rn int) uint32 {
	return 0xd61f0c1f | (uint32(rn) << 5)
}

func encNOP() uint32 {
	return 0xd503201f
}

func regOp(reg disassemble.Register) disassemble.Op {
	var op disassemble.Op
	op.NumRegisters = 1
	op.Registers[0] = reg
	return op
}
