package dyld

import (
	"testing"

	"github.com/blacktop/arm64-cgo/disassemble"
)

// encMOVK encodes a 64-bit `MOVK Xrd, #imm, LSL #shift` instruction word.
func encMOVK(rd int, imm uint16, shift uint) uint32 {
	return 0xf2800000 | ((uint32(shift/16) & 0x3) << 21) | (uint32(imm) << 5) | uint32(rd)
}

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

func TestSoftLinkApplyMoveKeepMergesShiftedImmediateExactlyOnce(t *testing.T) {
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
			var state [31]softLinkRegValue
			state[0] = softLinkRegValue{known: true, addr: start}
			softLinkApplyMoveKeep(decodeMOVK(t, 0, tt.imm, tt.shift), &state)
			if !state[0].known {
				t.Fatalf("register cleared after MOVK %s", tt.name)
			}
			if state[0].addr != tt.want {
				t.Fatalf("MOVK %s merged addr = %#016x, want %#016x", tt.name, state[0].addr, tt.want)
			}
		})
	}
}

func TestSoftLinkApplyMoveKeepClearsUnknownDest(t *testing.T) {
	t.Parallel()

	var state [31]softLinkRegValue
	state[0] = softLinkRegValue{}
	softLinkApplyMoveKeep(decodeMOVK(t, 0, 0x1234, 48), &state)
	if state[0].known {
		t.Fatalf("MOVK into unknown register should stay unknown, got %+v", state[0])
	}
}
