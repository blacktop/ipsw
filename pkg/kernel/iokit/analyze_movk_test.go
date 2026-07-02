package iokit

import (
	"testing"

	"github.com/blacktop/arm64-cgo/disassemble"
)

// encMOVK encodes a 64-bit `MOVK Xrd, #imm, LSL #shift` instruction word.
func encMOVK(rd int, imm uint16, shift uint) uint32 {
	return 0xf2800000 | ((uint32(shift/16) & 0x3) << 21) | (uint32(imm) << 5) | uint32(rd)
}

// decodeMOVK returns the disassembled MOVK so the test exercises the real
// operand representation (raw imm16 in Immediate plus ShiftValue), which is
// where the double-shift bug lived.
func decodeMOVK(t *testing.T, rd int, imm uint16, shift uint) *disassemble.Inst {
	t.Helper()
	var decoder disassemble.Decoder
	var inst disassemble.Inst
	if err := decoder.DecomposeInto(0, encMOVK(rd, imm, shift), &inst); err != nil {
		t.Fatalf("decode MOVK failed: %v", err)
	}
	if inst.Operation != disassemble.ARM64_MOVK {
		t.Fatalf("decoded operation = %v, want MOVK", inst.Operation)
	}
	return &inst
}

func TestApplyMoveKeepMergesShiftedImmediateExactlyOnce(t *testing.T) {
	t.Parallel()

	const start = uint64(0xaaaabbbbccccdddd)
	tests := []struct {
		name  string
		imm   uint16
		shift uint
		want  uint64
	}{
		{name: "lsl0", imm: 0x1234, shift: 0, want: 0xaaaabbbbcccc1234},
		{name: "lsl16", imm: 0x1234, shift: 16, want: 0xaaaabbbb1234dddd},
		{name: "lsl32", imm: 0x1234, shift: 32, want: 0xaaaa1234ccccdddd},
		{name: "lsl48", imm: 0x1234, shift: 48, want: 0x1234bbbbccccdddd},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			regs := make([]linearExpr, 31)
			regs[0] = linearExpr{valid: true, base: start}
			applyMoveKeep(decodeMOVK(t, 0, tt.imm, tt.shift), regs)
			if !regs[0].valid {
				t.Fatalf("register cleared after MOVK %s", tt.name)
			}
			if regs[0].base != tt.want {
				t.Fatalf("MOVK %s merged base = %#016x, want %#016x", tt.name, regs[0].base, tt.want)
			}
		})
	}
}

func TestApplyMoveKeepPreservesSymbolicExprForHighShift(t *testing.T) {
	t.Parallel()

	regs := make([]linearExpr, 31)
	regs[0] = linearExpr{valid: true, base: 0x1000, coeff: dispatchSizeClassic}
	applyMoveKeep(decodeMOVK(t, 0, 0x1234, 48), regs)
	if !regs[0].valid || regs[0].base != 0x1000 || regs[0].coeff != dispatchSizeClassic {
		t.Fatalf("symbolic expr mutated by high MOVK: %+v", regs[0])
	}
}

func TestApplyMoveKeepClearsSymbolicExprForLowShift(t *testing.T) {
	t.Parallel()

	regs := make([]linearExpr, 31)
	regs[0] = linearExpr{valid: true, base: 0x1000, coeff: dispatchSizeClassic}
	applyMoveKeep(decodeMOVK(t, 0, 0x1234, 16), regs)
	if regs[0].valid {
		t.Fatalf("low MOVK into symbolic expr should clear register, got %+v", regs[0])
	}
}
