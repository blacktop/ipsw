package xref

import (
	"testing"

	"github.com/blacktop/arm64-cgo/disassemble"
)

func decodeOne(t *testing.T, raw uint32) *disassemble.Inst {
	t.Helper()
	var inst disassemble.Inst
	var dec disassemble.Decoder
	if err := dec.DecomposeInto(0x100000000, raw, &inst); err != nil {
		t.Fatalf("decode %#08x: %v", raw, err)
	}
	return &inst
}

// encLDRA encodes an LDRAA/LDRAB. The byte offset is scaled by 8 into the
// encoded 10-bit signed field {S:imm9}; writeback selects the pre-index form.
func encLDRA(keyB, writeback bool, off int64, rn, rt int) uint32 {
	v10 := uint32(uint64(off/8) & 0x3ff)
	s := (v10 >> 9) & 1
	imm9 := v10 & 0x1ff
	var m, w uint32
	if keyB {
		m = 1
	}
	if writeback {
		w = 1
	}
	return (0b11 << 30) | (0b111 << 27) | (m << 23) | (s << 22) | (1 << 21) |
		(imm9 << 12) | (w << 11) | (1 << 10) | (uint32(rn) << 5) | uint32(rt)
}

func encAUTDA(rd, rn int) uint32 { return 0xDAC11800 | (uint32(rn) << 5) | uint32(rd) }
func encAUTDB(rd, rn int) uint32 { return 0xDAC11C00 | (uint32(rn) << 5) | uint32(rd) }
func encAUTIA(rd, rn int) uint32 { return 0xDAC11000 | (uint32(rn) << 5) | uint32(rd) }
func encAUTIB(rd, rn int) uint32 { return 0xDAC11400 | (uint32(rn) << 5) | uint32(rd) }
func encAUTDZA(rd int) uint32    { return 0xDAC13BE0 | uint32(rd) }

func encBLRAA(rn, rm int) uint32 { return 0xD73F0800 | (uint32(rn) << 5) | uint32(rm) }
func encBLRAB(rn, rm int) uint32 { return 0xD73F0C00 | (uint32(rn) << 5) | uint32(rm) }

func xreg(n int) disassemble.Register { return disassemble.REG_X0 + disassemble.Register(n) }

func TestDecodeLdrAuth(t *testing.T) {
	tests := []struct {
		name string
		raw  uint32
		want LdrAuth
	}{
		{
			name: "LDRAA offset",
			raw:  encLDRA(false, false, 0x20, 2, 1),
			want: LdrAuth{DestReg: xreg(1), BaseReg: xreg(2), Offset: 0x20},
		},
		{
			name: "LDRAA pre-index writeback",
			raw:  encLDRA(false, true, 0x40, 3, 5),
			want: LdrAuth{DestReg: xreg(5), BaseReg: xreg(3), Offset: 0x40, Writeback: true},
		},
		{
			name: "LDRAB offset",
			raw:  encLDRA(true, false, 0x8, 4, 6),
			want: LdrAuth{DestReg: xreg(6), BaseReg: xreg(4), Offset: 0x8, KeyB: true},
		},
		{
			name: "LDRAA negative offset",
			raw:  encLDRA(false, false, -0x8, 2, 1),
			want: LdrAuth{DestReg: xreg(1), BaseReg: xreg(2), Offset: -0x8},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst := decodeOne(t, tt.raw)
			if !IsLdrAuth(inst.Operation) {
				t.Fatalf("IsLdrAuth(%s)=false", inst.Operation)
			}
			got, ok := DecodeLdrAuth(inst)
			if !ok {
				t.Fatalf("DecodeLdrAuth ok=false")
			}
			if got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestDecodeLdrAuthRejectsPlainLoad(t *testing.T) {
	inst := decodeOne(t, encLDRUnsigned(1, 2, 0x20))
	if IsLdrAuth(inst.Operation) {
		t.Fatalf("plain LDR classified as authenticated load")
	}
	if _, ok := DecodeLdrAuth(inst); ok {
		t.Fatalf("DecodeLdrAuth accepted a plain LDR")
	}
}

func TestDecodeSeparateAuthAfterLoad(t *testing.T) {
	// LDR X8,[X0,#0x40] then AUTDA X8,X9 (the un-fused form).
	load := decodeOne(t, encLDRUnsigned(8, 0, 0x40))
	if IsLdrAuth(load.Operation) {
		t.Fatalf("plain LDR should not be an authenticated load")
	}
	auth := decodeOne(t, encAUTDA(8, 9))
	if !IsAuthPtr(auth.Operation) {
		t.Fatalf("AUTDA not recognized as auth-ptr")
	}
	got, ok := DecodeAuthPtr(auth)
	if !ok {
		t.Fatalf("DecodeAuthPtr ok=false")
	}
	want := AuthPtr{DestReg: xreg(8), ModifierReg: xreg(9), HasModifier: true, Data: true}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestDecodeAuthPtr(t *testing.T) {
	tests := []struct {
		name string
		raw  uint32
		want AuthPtr
	}{
		{
			name: "AUTDA data key A",
			raw:  encAUTDA(0, 1),
			want: AuthPtr{DestReg: xreg(0), ModifierReg: xreg(1), HasModifier: true, Data: true},
		},
		{
			name: "AUTDB data key B",
			raw:  encAUTDB(0, 1),
			want: AuthPtr{DestReg: xreg(0), ModifierReg: xreg(1), HasModifier: true, Data: true, KeyB: true},
		},
		{
			name: "AUTIA instr key A",
			raw:  encAUTIA(2, 3),
			want: AuthPtr{DestReg: xreg(2), ModifierReg: xreg(3), HasModifier: true},
		},
		{
			name: "AUTIB instr key B",
			raw:  encAUTIB(2, 3),
			want: AuthPtr{DestReg: xreg(2), ModifierReg: xreg(3), HasModifier: true, KeyB: true},
		},
		{
			name: "AUTDZA zero modifier",
			raw:  encAUTDZA(4),
			want: AuthPtr{DestReg: xreg(4), ModifierReg: disassemble.REG_NONE, Data: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst := decodeOne(t, tt.raw)
			if !IsAuthPtr(inst.Operation) {
				t.Fatalf("IsAuthPtr(%s)=false", inst.Operation)
			}
			got, ok := DecodeAuthPtr(inst)
			if !ok {
				t.Fatalf("DecodeAuthPtr ok=false")
			}
			if got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestDecodeMovkShift48(t *testing.T) {
	inst := decodeOne(t, encMOVK(3, 0x1234, 48))
	dest, imm, ok := DecodeMovkShift48(inst)
	if !ok {
		t.Fatalf("DecodeMovkShift48 ok=false for LSL#48")
	}
	if dest != xreg(3) || imm != 0x1234 {
		t.Fatalf("got dest=%s imm=%#x, want x3 0x1234", dest, imm)
	}
}

func TestDecodeMovkShift48RejectsLSL32(t *testing.T) {
	inst := decodeOne(t, encMOVK(3, 0x1234, 32))
	if _, _, ok := DecodeMovkShift48(inst); ok {
		t.Fatalf("LSL#32 MOVK mistaken for LSL#48 discriminator")
	}
}

func TestDecodeMovkShift48RejectsMOVZ(t *testing.T) {
	inst := decodeOne(t, encMOVZ(3, 0x1234, 48))
	if _, _, ok := DecodeMovkShift48(inst); ok {
		t.Fatalf("MOVZ mistaken for MOVK discriminator")
	}
}

func TestDecodeAuthCallReg(t *testing.T) {
	tests := []struct {
		name string
		raw  uint32
		want AuthCall
	}{
		{
			name: "BLRAA key A",
			raw:  encBLRAA(8, 9),
			want: AuthCall{TargetReg: xreg(8), ModifierReg: xreg(9)},
		},
		{
			name: "BLRAB key B",
			raw:  encBLRAB(8, 9),
			want: AuthCall{TargetReg: xreg(8), ModifierReg: xreg(9), KeyB: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst := decodeOne(t, tt.raw)
			got, ok := DecodeAuthCallReg(inst)
			if !ok {
				t.Fatalf("DecodeAuthCallReg ok=false")
			}
			if got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestDecodeAuthCallRegRejectsZeroModifierForm(t *testing.T) {
	// BLRAAZ has no modifier register and must not be decoded as a register-form
	// authenticated call.
	inst := decodeOne(t, encBLRAAZ(8))
	if inst.Operation != disassemble.ARM64_BLRAAZ {
		t.Fatalf("expected BLRAAZ, got %s", inst.Operation)
	}
	if _, ok := DecodeAuthCallReg(inst); ok {
		t.Fatalf("BLRAAZ decoded as register-form BLRAA")
	}
}
