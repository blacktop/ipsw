package cpp

import (
	"testing"

	"github.com/blacktop/arm64-cgo/disassemble"
)

func testOp(op disassemble.Operand) disassemble.Op {
	out := disassemble.Op{
		Class:          op.Class,
		ArrSpec:        op.ArrSpec,
		Condition:      op.Condition,
		SysReg:         op.SysReg,
		LaneUsed:       op.LaneUsed,
		Lane:           op.Lane,
		Immediate:      op.Immediate,
		ShiftType:      op.ShiftType,
		ShiftValueUsed: op.ShiftValueUsed,
		ShiftValue:     op.ShiftValue,
		Extend:         op.Extend,
		SignedImm:      op.SignedImm,
		PredQual:       op.PredQual,
		MulVl:          op.MulVl,
		Tile:           op.Tile,
		Slice:          op.Slice,
	}
	out.NumRegisters = uint8(copy(out.Registers[:], op.Registers))
	return out
}

func testInst(addr uint64, op disassemble.Operation, operands ...disassemble.Operand) *disassemble.Inst {
	inst := &disassemble.Inst{
		Address:   addr,
		Operation: op,
		NumOps:    uint8(len(operands)),
	}
	for idx := range operands {
		inst.Operands[idx] = testOp(operands[idx])
	}
	return inst
}

func TestBuildMicroPlanMarksAnchorStoreAndPAC(t *testing.T) {
	start := uint64(0x2000)
	anchor := uint64(0x2040)
	data := wordsToBytes(
		encodeBL(start, anchor),
		0xdac10230, // pacia x16, x17
		0xf9000010, // str x16, [x0]
		0xd65f03c0, // ret
	)

	plan := buildMicroPlan(start, data, func(target uint64) bool { return target == anchor }, len(data)-4)

	if len(plan.anchorBLOffsets) != 1 || plan.anchorBLOffsets[0] != 0 {
		t.Fatalf("anchorBLOffsets = %#v, want [0]", plan.anchorBLOffsets)
	}
	if len(plan.branchEventOffsets) != 1 || plan.branchEventOffsets[0] != 0 {
		t.Fatalf("branchEventOffsets = %#v, want [0]", plan.branchEventOffsets)
	}
	if len(plan.x16CandidateOffsets) != 1 || plan.x16CandidateOffsets[0] != 4 {
		t.Fatalf("x16CandidateOffsets = %#v, want [4]", plan.x16CandidateOffsets)
	}
	if len(plan.storeToX0Offsets) != 1 || plan.storeToX0Offsets[0] != 8 {
		t.Fatalf("storeToX0Offsets = %#v, want [8]", plan.storeToX0Offsets)
	}
	if len(plan.retOffsets) != 1 || plan.retOffsets[0] != 12 {
		t.Fatalf("retOffsets = %#v, want [12]", plan.retOffsets)
	}
	if plan.tags[0]&microTagBL == 0 {
		t.Fatalf("expected BL tag at offset 0")
	}
	if plan.tags[1]&microTagX16Candidate == 0 {
		t.Fatalf("expected x16 candidate tag at offset 4")
	}
	if plan.tags[2]&microTagStoreToX0 == 0 {
		t.Fatalf("expected store-to-x0 tag at offset 8")
	}
}

func TestApplyMicroInstructionTracksAddressMaterializationAndMoves(t *testing.T) {
	scanner := &Scanner{}
	state := newMicroState(nil, 0x1000)
	state.setKnownBase(1, 0x1000)

	scanner.applyMicroInstruction(state, testInst(0x1000, disassemble.ARM64_ADD,
		disassemble.Operand{Registers: []disassemble.Register{disassemble.REG_X0}},
		disassemble.Operand{Registers: []disassemble.Register{disassemble.REG_X1}},
		disassemble.Operand{Class: disassemble.IMM64, Immediate: 0x20},
	))
	if got, want := state.GetX(0), uint64(0x1020); got != want {
		t.Fatalf("x0 = %#x, want %#x", got, want)
	}
	if got, want := state.regBase[0], uint64(0x1020); got != want {
		t.Fatalf("regBase[x0] = %#x, want %#x", got, want)
	}

	scanner.applyMicroInstruction(state, testInst(0x1004, disassemble.ARM64_MOV,
		disassemble.Operand{Registers: []disassemble.Register{disassemble.REG_X2}},
		disassemble.Operand{Registers: []disassemble.Register{disassemble.REG_X0}},
	))
	if got, want := state.GetX(2), uint64(0x1020); got != want {
		t.Fatalf("x2 = %#x, want %#x", got, want)
	}

	scanner.applyMicroInstruction(state, testInst(0x1008, disassemble.ARM64_ORR,
		disassemble.Operand{Registers: []disassemble.Register{disassemble.REG_X3}},
		disassemble.Operand{Registers: []disassemble.Register{disassemble.REG_XZR}},
		disassemble.Operand{Registers: []disassemble.Register{disassemble.REG_X2}},
	))
	if got, want := state.GetX(3), uint64(0x1020); got != want {
		t.Fatalf("x3 = %#x, want %#x", got, want)
	}
	if got, want := state.regBase[3], uint64(0x1020); got != want {
		t.Fatalf("regBase[x3] = %#x, want %#x", got, want)
	}
}

func TestApplyMicroInstructionLoadsFromTrackedStackSlot(t *testing.T) {
	scanner := &Scanner{}
	state := newMicroState(nil, 0x3000)
	state.sp = 0x4000
	state.writeStack(0x4000, 0xfeedface)

	scanner.applyMicroInstruction(state, testInst(0x3000, disassemble.ARM64_LDR,
		disassemble.Operand{Registers: []disassemble.Register{disassemble.REG_X2}},
		disassemble.Operand{Class: disassemble.MEM_OFFSET, Registers: []disassemble.Register{disassemble.REG_SP}, Immediate: 0},
	))

	if got, want := state.GetX(2), uint64(0xfeedface); got != want {
		t.Fatalf("x2 = %#x, want %#x", got, want)
	}
	if got, want := state.regLoadAddr[2], uint64(0x4000); got != want {
		t.Fatalf("regLoadAddr[x2] = %#x, want %#x", got, want)
	}
}

func TestApplyMicroInstructionDoesNotMaterializeUnknownDynamicLoad(t *testing.T) {
	scanner := &Scanner{}
	state := newMicroState(nil, 0x5000)
	state.setKnownValue(1, 0xfffffe0001234000)

	scanner.applyMicroInstruction(state, testInst(0x5000, disassemble.ARM64_LDR,
		disassemble.Operand{Registers: []disassemble.Register{disassemble.REG_X0}},
		disassemble.Operand{Class: disassemble.MEM_OFFSET, Registers: []disassemble.Register{disassemble.REG_X1}, Immediate: 0},
	))

	if got := state.GetX(0); got != 0 {
		t.Fatalf("x0 = %#x, want 0 for unsupported dynamic load", got)
	}
	if got := state.regLoadAddr[0]; got != 0 {
		t.Fatalf("regLoadAddr[x0] = %#x, want 0 for unsupported dynamic load", got)
	}
}

func TestApplyMicroInstructionZeroExtendsWRegisterWrites(t *testing.T) {
	scanner := &Scanner{}
	state := newMicroState(nil, 0x6000)
	state.setKnownValue(1, 0x1_0000_0001)

	scanner.applyMicroInstruction(state, testInst(0x6000, disassemble.ARM64_MOV,
		disassemble.Operand{Registers: []disassemble.Register{disassemble.REG_W0}},
		disassemble.Operand{Registers: []disassemble.Register{disassemble.REG_X1}},
	))

	if got, want := state.GetX(0), uint64(1); got != want {
		t.Fatalf("x0 = %#x, want %#x after W write zero-extension", got, want)
	}
	if got := state.regBase[0]; got != 0 {
		t.Fatalf("regBase[x0] = %#x, want 0 after W write", got)
	}
}

func TestApplyMicroInstructionClearsUnsupportedDestination(t *testing.T) {
	scanner := &Scanner{}
	state := newMicroState(nil, 0x7000)
	state.setKnownValue(0, 0xfeedface)

	scanner.applyMicroInstruction(state, testInst(0x7000, disassemble.ARM64_CSEL,
		disassemble.Operand{Registers: []disassemble.Register{disassemble.REG_X0}},
		disassemble.Operand{Registers: []disassemble.Register{disassemble.REG_X1}},
		disassemble.Operand{Registers: []disassemble.Register{disassemble.REG_X2}},
	))

	if got := state.GetX(0); got != 0 {
		t.Fatalf("x0 = %#x, want 0 after unsupported destination write", got)
	}
}

func TestLooksLikeRecoveredClassName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{name: "IOMemoryMap", want: true},
		{name: "OSValueObject<IOAccessoryIDBusTransport::TransferData>", want: true},
		{name: "AGX·PI_300·P·A0·Accelerator", want: true},
		{name: "vm_map_init", want: false},
		{name: "com.apple.xnu.accounting_health", want: false},
		{name: "/arm-io/sgx", want: false},
		{name: "\"AppleSEPKeyStore\"", want: false},
		{name: "0 == (status)", want: false},
	}

	for _, tc := range tests {
		if got := looksLikeRecoveredClassName(tc.name); got != tc.want {
			t.Fatalf("looksLikeRecoveredClassName(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestRecoveredClassNameScorePrefersClassLikeNames(t *testing.T) {
	if got, want := recoveredClassNameScore("UnknownClass_0xfffffe0007004000"), 1; got != want {
		t.Fatalf("unknown score = %d, want %d", got, want)
	}
	if got, want := recoveredClassNameScore("vm_map_init"), 1; got != want {
		t.Fatalf("function-like score = %d, want %d", got, want)
	}
	if got, want := recoveredClassNameScore("IOMemoryMap"), 3; got != want {
		t.Fatalf("class-like score = %d, want %d", got, want)
	}
}
