package pacx

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// ---- instruction encoders (synthetic; no real firmware bytes) ----------------

func words(ws ...uint32) []byte {
	var buf bytes.Buffer
	for _, w := range ws {
		_ = binary.Write(&buf, binary.LittleEndian, w)
	}
	return buf.Bytes()
}

// encLDRA encodes LDRAA/LDRAB. The byte offset is scaled by 8 into the encoded
// 10-bit signed field {S:imm9}; writeback selects the pre-index (!) form.
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

// encLDRUnsigned encodes a plain LDR Xt,[Xn,#imm] (unsigned scaled offset).
func encLDRUnsigned(rt, rn int, imm uint64) uint32 {
	return 0xf9400000 | (uint32((imm/8)&0xfff) << 10) | (uint32(rn) << 5) | uint32(rt)
}

// encLDRpre encodes a plain LDR Xt,[Xn,#imm]! (pre-index writeback). The imm9 is
// an unscaled signed byte offset.
func encLDRpre(rt, rn int, off int64) uint32 {
	imm9 := uint32(uint64(off) & 0x1ff)
	return 0xf8400c00 | (imm9 << 12) | (uint32(rn) << 5) | uint32(rt)
}

// encSTPpre encodes STP Xt1,Xt2,[Xn,#imm]! (pre-index writeback). The imm7 is a
// signed byte offset scaled by 8 for 64-bit register pairs.
func encSTPpre(rt, rt2, rn int, off int64) uint32 {
	imm7 := uint32(uint64(off/8) & 0x7f)
	return 0xa9800000 | (imm7 << 15) | (uint32(rt2) << 10) | (uint32(rn) << 5) | uint32(rt)
}

// encADD encodes ADD Xd,Xn,#imm (unshifted 12-bit immediate).
func encADD(rd, rn int, imm uint64) uint32 {
	return 0x91000000 | (uint32(imm&0xfff) << 10) | (uint32(rn) << 5) | uint32(rd)
}

// encADDW encodes ADD Wd,Wn,#imm (32-bit, sf=0): the sum zero-extends into Xd, so
// it does not preserve a 64-bit authenticated pointer.
func encADDW(rd, rn int, imm uint64) uint32 {
	return 0x11000000 | (uint32(imm&0xfff) << 10) | (uint32(rn) << 5) | uint32(rd)
}

// encMOVK encodes MOVK Xd,#imm,LSL#shift (shift in bits: 0/16/32/48).
func encMOVK(rd int, imm uint16, shift uint) uint32 {
	return 0xf2800000 | ((uint32(shift/16) & 0x3) << 21) | (uint32(imm) << 5) | uint32(rd)
}

// encMOVZ encodes MOVZ Xd,#imm,LSL#shift.
func encMOVZ(rd int, imm uint16, shift uint) uint32 {
	return 0xd2800000 | ((uint32(shift/16) & 0x3) << 21) | (uint32(imm) << 5) | uint32(rd)
}

// encMOVreg encodes MOV Xd,Xm (ORR Xd,XZR,Xm).
func encMOVreg(rd, rm int) uint32 {
	return 0xaa0003e0 | (uint32(rm) << 16) | uint32(rd)
}

// encMOVWreg encodes MOV Wd,Wm (ORR Wd,WZR,Wm): a 32-bit register move that
// zero-extends and so redefines the full 64-bit Xd.
func encMOVWreg(rd, rm int) uint32 {
	return 0x2a0003e0 | (uint32(rm) << 16) | uint32(rd)
}

// encORRLSL encodes ORR Xd,Xn,Xm,LSL#shift.
func encORRLSL(rd, rn, rm int, shift uint) uint32 {
	return 0xaa000000 | (uint32(rm) << 16) | (uint32(shift&0x3f) << 10) | (uint32(rn) << 5) | uint32(rd)
}

func encADRP(rd int) uint32      { return 0x90000000 | uint32(rd) }
func encAUTDA(rd, rn int) uint32 { return 0xdac11800 | (uint32(rn) << 5) | uint32(rd) }
func encAUTIA(rd, rn int) uint32 { return 0xdac11000 | (uint32(rn) << 5) | uint32(rd) }
func encAUTDZA(rd int) uint32    { return 0xdac13be0 | uint32(rd) }
func encBLRAA(rn, rm int) uint32 { return 0xd73f0800 | (uint32(rn) << 5) | uint32(rm) }
func encBLRAB(rn, rm int) uint32 { return 0xd73f0c00 | (uint32(rn) << 5) | uint32(rm) }
func encBLRAAZ(rn int) uint32    { return 0xd63f081f | (uint32(rn) << 5) }
func encBLR(rn int) uint32       { return 0xd63f0000 | (uint32(rn) << 5) }
func encBL() uint32              { return 0x94000000 }
func encBR(rn int) uint32        { return 0xd61f0000 | (uint32(rn) << 5) }
func encB() uint32               { return 0x14000000 }
func encRET() uint32             { return 0xd65f03c0 }

const fnBase = uint64(0xfffffe0007100000)

// ---- tests -------------------------------------------------------------------

// The dominant fused form: the modifier register is the LDRAA writeback base, so
// the slot offset is the LDRAA displacement and the depac anchor is the LDRAA
// itself.
func TestBuildCallSiteIndexFusedLDRAA(t *testing.T) {
	t.Parallel()
	// ldraa x8,[x16,#0x10]! ; movk x16,#0x1234,lsl#48 ; blraa x8,x16
	code := words(
		encLDRA(false, true, 0x10, 16, 8),
		encMOVK(16, 0x1234, 48),
		encBLRAA(8, 16),
	)
	idx := BuildCallSiteIndex([]FuncBody{{Addr: fnBase, Code: code}}, 0)

	sites := idx.Sites(0x10, 0x1234)
	if len(sites) != 1 {
		t.Fatalf("Sites(0x10,0x1234)=%d, want 1; idx=%+v", len(sites), idx)
	}
	if sites[0].Addr != fnBase+8 {
		t.Fatalf("call addr=%#x, want %#x", sites[0].Addr, fnBase+8)
	}
	if sites[0].CallerFuncAddr != fnBase {
		t.Fatalf("caller=%#x, want %#x", sites[0].CallerFuncAddr, fnBase)
	}
	if len(idx) != 1 {
		t.Fatalf("index has %d keys, want 1: %+v", len(idx), idx)
	}
}

// Split form: the vtable pointer is authenticated in place (AUTDA), the slot
// address is formed with an ADD, and the modifier is a rename of it. The offset
// comes from the ADD immediate and the anchor is the AUTDA.
func TestBuildCallSiteIndexSplitAutdaWithAdd(t *testing.T) {
	t.Parallel()
	// autda x9,x3 ; add x17,x9,#0x18 ; ldr x8,[x17] ; movk x17,#0xbeef,lsl#48 ; blraa x8,x17
	code := words(
		encAUTDA(9, 3),
		encADD(17, 9, 0x18),
		encLDRUnsigned(8, 17, 0),
		encMOVK(17, 0xbeef, 48),
		encBLRAA(8, 17),
	)
	idx := BuildCallSiteIndex([]FuncBody{{Addr: fnBase, Code: code}}, 0)

	sites := idx.Sites(0x18, 0xbeef)
	if len(sites) != 1 {
		t.Fatalf("Sites(0x18,0xbeef)=%d, want 1; idx=%+v", len(sites), idx)
	}
	if sites[0].Addr != fnBase+16 {
		t.Fatalf("call addr=%#x, want %#x", sites[0].Addr, fnBase+16)
	}
}

// Captured real dispatch shape: the modifier is a MOV rename of the depac'd
// vtable pointer (offset 0), the target register is loaded separately.
func TestBuildCallSiteIndexModifierRenameChain(t *testing.T) {
	t.Parallel()
	// autdza x25 ; ldr x8,[x25] ; mov x17,x25 ; movk x17,#0xc7a0,lsl#48 ; blraa x8,x17
	code := words(
		encAUTDZA(25),
		encLDRUnsigned(8, 25, 0),
		encMOVreg(17, 25),
		encMOVK(17, 0xc7a0, 48),
		encBLRAA(8, 17),
	)
	idx := BuildCallSiteIndex([]FuncBody{{Addr: fnBase, Code: code}}, 0)

	if sites := idx.Sites(0x0, 0xc7a0); len(sites) != 1 {
		t.Fatalf("Sites(0x0,0xc7a0)=%d, want 1; idx=%+v", len(sites), idx)
	}
}

// The offset is recovered from the MODIFIER register chain, never the target
// register. Here the target (x8) is loaded through a DIFFERENT LDRAA at offset
// 0x30, while the modifier (x17) is built at offset 0x40 off an AUTDA'd base. The
// recovered key must be (0x40, hash), and (0x30, hash) must not appear -- this
// fails on the old target-register model, which would report 0x30.
func TestBuildCallSiteIndexOffsetFromModifierNotTarget(t *testing.T) {
	t.Parallel()
	code := words(
		encAUTDA(9, 3),
		encADD(17, 9, 0x40),
		encLDRA(false, true, 0x30, 16, 8),
		encMOVK(17, 0x1234, 48),
		encBLRAA(8, 17),
	)
	idx := BuildCallSiteIndex([]FuncBody{{Addr: fnBase, Code: code}}, 0)

	if sites := idx.Sites(0x40, 0x1234); len(sites) != 1 {
		t.Fatalf("Sites(0x40,0x1234)=%d, want 1; idx=%+v", len(sites), idx)
	}
	if sites := idx.Sites(0x30, 0x1234); len(sites) != 0 {
		t.Fatalf("Sites(0x30,0x1234)=%d, want 0 (target-register offset leaked)", len(sites))
	}
}

// A pre-index plain LDR advances the slot address; its displacement accumulates
// into the offset while the tracked register is unchanged.
func TestBuildCallSiteIndexOffsetFromLdrWriteback(t *testing.T) {
	t.Parallel()
	// autda x9,x3 ; ldr x8,[x9,#0x8]! ; mov x17,x9 ; movk x17,#0x2222,lsl#48 ; blraa x8,x17
	code := words(
		encAUTDA(9, 3),
		encLDRpre(8, 9, 0x8),
		encMOVreg(17, 9),
		encMOVK(17, 0x2222, 48),
		encBLRAA(8, 17),
	)
	idx := BuildCallSiteIndex([]FuncBody{{Addr: fnBase, Code: code}}, 0)

	if sites := idx.Sites(0x8, 0x2222); len(sites) != 1 {
		t.Fatalf("Sites(0x8,0x2222)=%d, want 1; idx=%+v", len(sites), idx)
	}
}

// A MOV rename on the target register is irrelevant to the modifier-chain walk.
func TestBuildCallSiteIndexInterveningTargetMOV(t *testing.T) {
	t.Parallel()
	// ldraa x8,[x16,#0x20]! ; movk x16,#0x5555,lsl#48 ; mov x9,x8 ; blraa x9,x16
	code := words(
		encLDRA(false, true, 0x20, 16, 8),
		encMOVK(16, 0x5555, 48),
		encMOVreg(9, 8),
		encBLRAA(9, 16),
	)
	idx := BuildCallSiteIndex([]FuncBody{{Addr: fnBase, Code: code}}, 0)

	if sites := idx.Sites(0x20, 0x5555); len(sites) != 1 {
		t.Fatalf("Sites(0x20,0x5555)=%d, want 1; idx=%+v", len(sites), idx)
	}
}

func TestBuildCallSiteIndexExcludesZeroModifierForm(t *testing.T) {
	t.Parallel()
	// ldraa x8,[x16,#0x10]! ; movk x16,#0x1234,lsl#48 ; blraaz x8 (no modifier reg)
	code := words(
		encLDRA(false, true, 0x10, 16, 8),
		encMOVK(16, 0x1234, 48),
		encBLRAAZ(8),
	)
	idx := BuildCallSiteIndex([]FuncBody{{Addr: fnBase, Code: code}}, 0)
	if len(idx) != 0 {
		t.Fatalf("BLRAAZ produced %d keys, want 0: %+v", len(idx), idx)
	}
}

func TestBuildCallSiteIndexExcludesNonAuthBLR(t *testing.T) {
	t.Parallel()
	// ldraa x8,[x16,#0x10]! ; movk x16,#0x1234,lsl#48 ; blr x8 (unauthenticated)
	code := words(
		encLDRA(false, true, 0x10, 16, 8),
		encMOVK(16, 0x1234, 48),
		encBLR(8),
	)
	idx := BuildCallSiteIndex([]FuncBody{{Addr: fnBase, Code: code}}, 0)
	if len(idx) != 0 {
		t.Fatalf("non-auth BLR produced %d keys, want 0: %+v", len(idx), idx)
	}
}

// No depac anchor on the modifier chain: the modifier is a pure constant
// (MOVZ+MOVK), a static/devirtualized dispatch, excluded.
func TestBuildCallSiteIndexExcludesStaticConstantModifier(t *testing.T) {
	t.Parallel()
	// ldr x8,[x0] ; movz x17,#0 ; movk x17,#0x1234,lsl#48 ; blraa x8,x17
	code := words(
		encLDRUnsigned(8, 0, 0),
		encMOVZ(17, 0, 0),
		encMOVK(17, 0x1234, 48),
		encBLRAA(8, 17),
	)
	idx := BuildCallSiteIndex([]FuncBody{{Addr: fnBase, Code: code}}, 0)
	if len(idx) != 0 {
		t.Fatalf("static constant modifier produced %d keys, want 0: %+v", len(idx), idx)
	}
}

// A modifier whose address is a compile-time constant (ADRP+ADD, no
// authenticated load) is a static vtable dispatch: no depac anchor, excluded.
func TestBuildCallSiteIndexExcludesStaticAddressModifier(t *testing.T) {
	t.Parallel()
	// adrp x17,... ; add x17,x17,#0x20 ; ldr x8,[x17] ; movk x17,#0x1234,lsl#48 ; blraa x8,x17
	code := words(
		encADRP(17),
		encADD(17, 17, 0x20),
		encLDRUnsigned(8, 17, 0),
		encMOVK(17, 0x1234, 48),
		encBLRAA(8, 17),
	)
	idx := BuildCallSiteIndex([]FuncBody{{Addr: fnBase, Code: code}}, 0)
	if len(idx) != 0 {
		t.Fatalf("static address modifier produced %d keys, want 0: %+v", len(idx), idx)
	}
}

// A modifier set by a MOVK but never reaching a depac anchor within the window
// must not emit an edge (seen_depac is required).
func TestBuildCallSiteIndexRequiresDepacAnchor(t *testing.T) {
	t.Parallel()
	// mov x17,x9 ; movk x17,#0x1234,lsl#48 ; blraa x8,x17  (x9 never authenticated)
	code := words(
		encMOVreg(17, 9),
		encMOVK(17, 0x1234, 48),
		encBLRAA(8, 17),
	)
	idx := BuildCallSiteIndex([]FuncBody{{Addr: fnBase, Code: code}}, 0)
	if len(idx) != 0 {
		t.Fatalf("modifier without depac anchor produced %d keys, want 0: %+v", len(idx), idx)
	}
}

func TestBuildCallSiteIndexStopsAtControlFlowBarriers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		term uint32
	}{
		{name: "ret", term: encRET()},
		{name: "unconditional branch", term: encB()},
		{name: "branch register", term: encBR(9)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// autda x9,x3 ; add x17,x9,#0x18 ; <barrier> ; movk x17,#0x1234,lsl#48 ; blraa x8,x17
			code := words(
				encAUTDA(9, 3),
				encADD(17, 9, 0x18),
				tt.term,
				encMOVK(17, 0x1234, 48),
				encBLRAA(8, 17),
			)
			idx := BuildCallSiteIndex([]FuncBody{{Addr: fnBase, Code: code}}, 0)
			if sites := idx.Sites(0x18, 0x1234); len(sites) != 0 {
				t.Fatalf("Sites(0x18,0x1234)=%d, want 0 (walk crossed %s)", len(sites), tt.name)
			}
			if len(idx) != 0 {
				t.Fatalf("index has %d keys, want 0 (fabricated edge across %s): %+v", len(idx), tt.name, idx)
			}
		})
	}
}

func TestBuildCallSiteIndexStopsAtVolatileCallClobber(t *testing.T) {
	t.Parallel()
	// autda x9,x3 ; add x17,x9,#0x18 ; bl callee ; movk x17,#0x1234,lsl#48 ; blraa x8,x17
	code := words(
		encAUTDA(9, 3),
		encADD(17, 9, 0x18),
		encBL(),
		encMOVK(17, 0x1234, 48),
		encBLRAA(8, 17),
	)
	idx := BuildCallSiteIndex([]FuncBody{{Addr: fnBase, Code: code}}, 0)
	if sites := idx.Sites(0x18, 0x1234); len(sites) != 0 {
		t.Fatalf("Sites(0x18,0x1234)=%d, want 0 (walk crossed call clobbering x17)", len(sites))
	}
	if len(idx) != 0 {
		t.Fatalf("index has %d keys, want 0 (fabricated edge across volatile call): %+v", len(idx), idx)
	}
}

func TestBuildCallSiteIndexRejectsInstructionKeyAuthAnchor(t *testing.T) {
	t.Parallel()
	// autia x17,x3 ; movk x17,#0x1234,lsl#48 ; blraa x8,x17
	code := words(
		encAUTIA(17, 3),
		encMOVK(17, 0x1234, 48),
		encBLRAA(8, 17),
	)
	idx := BuildCallSiteIndex([]FuncBody{{Addr: fnBase, Code: code}}, 0)
	if sites := idx.Sites(0, 0x1234); len(sites) != 0 {
		t.Fatalf("Sites(0,0x1234)=%d, want 0 (instruction-key auth accepted as vtable anchor)", len(sites))
	}
	if len(idx) != 0 {
		t.Fatalf("index has %d keys, want 0 (fabricated instruction-key auth edge): %+v", len(idx), idx)
	}
}

func TestBuildCallSiteIndexNonZeroHashNoDoubleShift(t *testing.T) {
	t.Parallel()
	// Guards the MOVK #imm,LSL#48 shift handling: a top-bit-set hash must be
	// recovered verbatim (a stray <<48 would overflow it to zero).
	const hash = uint16(0x8123)
	// ldraa x8,[x16,#0x8]! ; movk x16,#0x8123,lsl#48 ; blrab x8,x16
	code := words(
		encLDRA(false, true, 0x8, 16, 8),
		encMOVK(16, hash, 48),
		encBLRAB(8, 16),
	)
	idx := BuildCallSiteIndex([]FuncBody{{Addr: fnBase, Code: code}}, 0)

	sites := idx.Sites(0x8, hash)
	if len(sites) != 1 {
		t.Fatalf("Sites(0x8,%#x)=%d, want 1; idx=%+v", hash, len(sites), idx)
	}
	if !sites[0].KeyB {
		t.Fatalf("BLRAB site KeyB=false, want true: %+v", sites[0])
	}
	for k := range idx {
		if k.Hash != hash {
			t.Fatalf("recovered hash %#x, want %#x", k.Hash, hash)
		}
	}
}

// A 32-bit write to the modifier register (mov w17,w5) zero-extends and redefines
// the full x17. The walk must treat it as a clobber of the tracked x17; otherwise
// it walks past the reuse, latches onto a stale earlier authenticated-base chain
// (autda x9 -> add x17,x9,#0x18), and fabricates a (0x18, hash) edge even though
// the real modifier is an unrelated 32-bit value.
func TestBuildCallSiteIndexNormalizesWXAliasClobber(t *testing.T) {
	t.Parallel()
	// autda x9,x3 ; add x17,x9,#0x18 ; ldr x8,[x17] ; mov w17,w5 ; movk x17,#0x1234,lsl#48 ; blraa x8,x17
	code := words(
		encAUTDA(9, 3),
		encADD(17, 9, 0x18),
		encLDRUnsigned(8, 17, 0),
		encMOVWreg(17, 5),
		encMOVK(17, 0x1234, 48),
		encBLRAA(8, 17),
	)
	idx := BuildCallSiteIndex([]FuncBody{{Addr: fnBase, Code: code}}, 0)
	if sites := idx.Sites(0x18, 0x1234); len(sites) != 0 {
		t.Fatalf("Sites(0x18,0x1234)=%d, want 0 (w17 clobber walked past -> fabricated edge)", len(sites))
	}
	if len(idx) != 0 {
		t.Fatalf("index has %d keys, want 0 (fabricated edge from stale chain): %+v", len(idx), idx)
	}
}

func TestBuildCallSiteIndexRejectsWRegisterModifierRename(t *testing.T) {
	t.Parallel()
	// autda x5,x3 ; ldr x8,[x5] ; mov w17,w5 ; movk x17,#0x1234,lsl#48 ; blraa x8,x17
	code := words(
		encAUTDA(5, 3),
		encLDRUnsigned(8, 5, 0),
		encMOVWreg(17, 5),
		encMOVK(17, 0x1234, 48),
		encBLRAA(8, 17),
	)
	idx := BuildCallSiteIndex([]FuncBody{{Addr: fnBase, Code: code}}, 0)
	if sites := idx.Sites(0, 0x1234); len(sites) != 0 {
		t.Fatalf("Sites(0,0x1234)=%d, want 0 (w17 rename preserved a truncated pointer)", len(sites))
	}
	if len(idx) != 0 {
		t.Fatalf("index has %d keys, want 0 (fabricated edge from W-register rename): %+v", len(idx), idx)
	}
}

func TestBuildCallSiteIndexRejectsShiftedORRModifierRename(t *testing.T) {
	t.Parallel()
	// autda x5,x3 ; ldr x8,[x5] ; orr x17,xzr,x5,lsl#1 ; movk x17,#0x1234,lsl#48 ; blraa x8,x17
	code := words(
		encAUTDA(5, 3),
		encLDRUnsigned(8, 5, 0),
		encORRLSL(17, 31, 5, 1),
		encMOVK(17, 0x1234, 48),
		encBLRAA(8, 17),
	)
	idx := BuildCallSiteIndex([]FuncBody{{Addr: fnBase, Code: code}}, 0)
	if sites := idx.Sites(0, 0x1234); len(sites) != 0 {
		t.Fatalf("Sites(0,0x1234)=%d, want 0 (shifted ORR treated as pointer rename)", len(sites))
	}
	if len(idx) != 0 {
		t.Fatalf("index has %d keys, want 0 (fabricated edge from shifted ORR): %+v", len(idx), idx)
	}
}

func TestBuildCallSiteIndexRejectsPairWritebackModifierClobber(t *testing.T) {
	t.Parallel()
	// autda x9,x3 ; add x17,x9,#0x18 ; ldr x8,[x17] ; stp x0,x1,[x17,#0x20]! ; movk x17,#0x1234,lsl#48 ; blraa x8,x17
	code := words(
		encAUTDA(9, 3),
		encADD(17, 9, 0x18),
		encLDRUnsigned(8, 17, 0),
		encSTPpre(0, 1, 17, 0x20),
		encMOVK(17, 0x1234, 48),
		encBLRAA(8, 17),
	)
	idx := BuildCallSiteIndex([]FuncBody{{Addr: fnBase, Code: code}}, 0)
	if sites := idx.Sites(0x18, 0x1234); len(sites) != 0 {
		t.Fatalf("Sites(0x18,0x1234)=%d, want 0 (pair writeback clobber walked past -> stale offset)", len(sites))
	}
	if len(idx) != 0 {
		t.Fatalf("index has %d keys, want 0 (fabricated edge from pair writeback): %+v", len(idx), idx)
	}
}

// A 32-bit ADD (add w17,w5,#8) zero-extends its 32-bit sum into x17 rather than
// preserving the authenticated 64-bit pointer x5+8. It must halt the walk; if the
// W-source is instead followed to x5's AUTDA anchor, a fabricated (0x8, hash) edge
// results.
func TestBuildCallSiteIndexRejectsWRegisterModifierAdd(t *testing.T) {
	t.Parallel()
	// autda x5,x3 ; add w17,w5,#8 ; ldr x8,[x17] ; movk x17,#0x1234,lsl#48 ; blraa x8,x17
	code := words(
		encAUTDA(5, 3),
		encADDW(17, 5, 8),
		encLDRUnsigned(8, 17, 0),
		encMOVK(17, 0x1234, 48),
		encBLRAA(8, 17),
	)
	idx := BuildCallSiteIndex([]FuncBody{{Addr: fnBase, Code: code}}, 0)
	if sites := idx.Sites(0x8, 0x1234); len(sites) != 0 {
		t.Fatalf("Sites(0x8,0x1234)=%d, want 0 (32-bit ADD zero-extends -> not a pointer offset)", len(sites))
	}
	if len(idx) != 0 {
		t.Fatalf("index has %d keys, want 0 (fabricated W-ADD edge): %+v", len(idx), idx)
	}
}

func TestBuildCallSiteIndexRecordsPerFunctionCaller(t *testing.T) {
	t.Parallel()
	// Two functions dispatch through the same (offset, hash); both sites recorded
	// with their own caller function address.
	fnA := fnBase
	fnB := fnBase + 0x1000
	body := func() []uint32 {
		return []uint32{
			encLDRA(false, true, 0x10, 16, 8),
			encMOVK(16, 0x2020, 48),
			encBLRAA(8, 16),
		}
	}
	idx := BuildCallSiteIndex([]FuncBody{
		{Addr: fnB, Code: words(body()...)},
		{Addr: fnA, Code: words(body()...)},
	}, 0)

	sites := idx.Sites(0x10, 0x2020)
	if len(sites) != 2 {
		t.Fatalf("Sites(0x10,0x2020)=%d, want 2; idx=%+v", len(sites), idx)
	}
	if sites[0].CallerFuncAddr != fnA || sites[1].CallerFuncAddr != fnB {
		t.Fatalf("callers not sorted by addr: %+v", sites)
	}
}
