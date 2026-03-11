package cpp

import "testing"

func encodeADR(from, to uint64, rd int) uint32 {
	imm := int64(to - from)
	immlo := uint32(imm & 0x3)
	immhi := uint32((imm >> 2) & 0x7ffff)
	return 0x10000000 | (immlo << 29) | (immhi << 5) | uint32(rd&0x1f)
}

func encodeADRP(from, to uint64, rd int) uint32 {
	pageFrom := from &^ 0xfff
	pageTo := to &^ 0xfff
	imm := int64(pageTo-pageFrom) >> 12
	immlo := uint32(imm & 0x3)
	immhi := uint32((imm >> 2) & 0x7ffff)
	return 0x90000000 | (immlo << 29) | (immhi << 5) | uint32(rd&0x1f)
}

func encodeADDImm(rn, rd int, imm uint64) uint32 {
	return 0x91000000 | (uint32(imm&0xfff) << 10) | (uint32(rn&0x1f) << 5) | uint32(rd&0x1f)
}

func encodeLDRUOff(rn, rt int, imm uint64) uint32 {
	return 0xf9400000 | (uint32((imm/8)&0xfff) << 10) | (uint32(rn&0x1f) << 5) | uint32(rt&0x1f)
}

func encodeBR(rn int) uint32 {
	return 0xd61f0000 | (uint32(rn&0x1f) << 5)
}

func TestCollectConstructorTargetsForStringRefsHandlesMultipleCandidates(t *testing.T) {
	start := uint64(0x1000)
	ref := uint64(0x1800)
	targetA := uint64(0x2000)
	targetB := uint64(0x2100)
	data := wordsToBytes(
		encodeADR(start, ref, 1),
		0xd503201f,
		encodeBL(start+8, targetA),
		encodeADR(start+12, ref, 1),
		0xd503201f,
		encodeB(start+20, targetB),
	)

	targets := collectConstructorTargetsForStringRefs(start, data, uint64Set{ref: {}}, nil)
	if !hasUint64Set(targets, targetA) || len(targets) != 1 {
		t.Fatalf("targets = %#v, want {%#x}", targets, targetA)
	}

	filtered := collectConstructorTargetsForStringRefs(start, data, uint64Set{ref: {}}, uint64Set{targetB: {}})
	if len(filtered) != 0 {
		t.Fatalf("filtered targets = %#v, want empty set", filtered)
	}
}

func TestImportStubReferenceTargetRecognizesDirectAndIndirectForms(t *testing.T) {
	ref := uint64(0x4000)
	start := uint64(0x2000)

	data := wordsToBytes(
		encodeADRP(start, ref, 16),
		encodeLDRUOff(16, 17, ref-(ref&^0xfff)),
		encodeBR(17),
	)
	if got, ok := importStubReferenceTarget(start, data, uint64Set{ref: {}}); !ok || got != ref {
		t.Fatalf("direct importStubReferenceTarget = (%#x, %v), want (%#x, true)", got, ok, ref)
	}

	start = 0x3000
	data = wordsToBytes(
		encodeADRP(start, ref, 9),
		encodeADDImm(9, 16, ref-(ref&^0xfff)),
		encodeLDRUOff(16, 17, 0),
		encodeBR(17),
	)
	if got, ok := importStubReferenceTarget(start, data, uint64Set{ref: {}}); !ok || got != ref {
		t.Fatalf("indirect importStubReferenceTarget = (%#x, %v), want (%#x, true)", got, ok, ref)
	}

	data = wordsToBytes(
		encodeADRP(start, ref, 9),
		encodeADDImm(9, 16, ref-(ref&^0xfff)),
		encodeLDRUOff(16, 17, 8),
		encodeBR(17),
	)
	if _, ok := importStubReferenceTarget(start, data, uint64Set{ref: {}}); ok {
		t.Fatal("importStubReferenceTarget unexpectedly accepted non-zero LDR offset")
	}
}

func TestFindPassThroughConstructorTargetRequiresSinglePassThroughBL(t *testing.T) {
	start := uint64(0x5000)
	target := uint64(0x5100)
	data := wordsToBytes(
		0xd503237f,
		0xd503201f,
		encodeBL(start+8, target),
	)
	if got, ok := findPassThroughConstructorTarget(start, data, uint64Set{target: {}}); !ok || got != target {
		t.Fatalf("findPassThroughConstructorTarget = (%#x, %v), want (%#x, true)", got, ok, target)
	}

	data = wordsToBytes(
		0xd2800001, // movz x1, #0
		encodeBL(start+4, target),
	)
	if _, ok := findPassThroughConstructorTarget(start, data, uint64Set{target: {}}); ok {
		t.Fatalf("findPassThroughConstructorTarget unexpectedly accepted clobbered x1")
	}

	data = wordsToBytes(
		0xd2800004, // movz x4, #0
		encodeBL(start+4, target),
	)
	if _, ok := findPassThroughConstructorTarget(start, data, uint64Set{target: {}}); ok {
		t.Fatalf("findPassThroughConstructorTarget unexpectedly accepted clobbered x4")
	}
}

func encodeSTPPreIndex(rt, rt2, rn int, imm int) uint32 {
	// stp Xt, Xt2, [Xn, #imm]!  (64-bit pre-index store pair)
	uimm := uint32(imm/8) & 0x7f
	return 0xa9800000 | (uimm << 15) | (uint32(rt2&0x1f) << 10) |
		(uint32(rn&0x1f) << 5) | uint32(rt&0x1f)
}

func encodeSTPOffset(rt, rt2, rn int, imm int) uint32 {
	// stp Xt, Xt2, [Xn, #imm]  (64-bit signed-offset store pair)
	uimm := uint32(imm/8) & 0x7f
	return 0xa9000000 | (uimm << 15) | (uint32(rt2&0x1f) << 10) |
		(uint32(rn&0x1f) << 5) | uint32(rt&0x1f)
}

func encodeMOV(rd, rm int) uint32 {
	// mov Xd, Xm  →  orr Xd, xzr, Xm
	return 0xaa0003e0 | (uint32(rm&0x1f) << 16) | uint32(rd&0x1f)
}

func TestFindPassThroughZoneWrapperPrologue(t *testing.T) {
	// Mimics the zone-aware OSMetaClass wrapper prologue:
	//   pacibsp; stp x24,x23,[sp,#-0x40]!; stp x22,x21,[sp,#0x10];
	//   stp x20,x19,[sp,#0x20]; stp fp,lr,[sp,#0x30];
	//   add fp,sp,#0x30; mov x22,x6; mov x21,x5; mov x19,x4;
	//   mov x23,x3; mov x20,x0; bl anchor
	start := uint64(0x8000)
	anchor := uint64(0x9000)
	data := wordsToBytes(
		0xd503237f, // pacibsp
		encodeSTPPreIndex(24, 23, 31, -0x40),
		encodeSTPOffset(22, 21, 31, 0x10),
		encodeSTPOffset(20, 19, 31, 0x20),
		encodeSTPOffset(29, 30, 31, 0x30),
		encodeADDImm(31, 29, 0x30), // add fp, sp, #0x30
		encodeMOV(22, 6),
		encodeMOV(21, 5),
		encodeMOV(19, 4),
		encodeMOV(23, 3),
		encodeMOV(20, 0),
		encodeBL(start+44, anchor),
	)
	got, ok := findPassThroughConstructorTarget(
		start, data, uint64Set{anchor: {}},
	)
	if !ok || got != anchor {
		t.Fatalf("findPassThroughConstructorTarget = (%#x, %v), "+
			"want (%#x, true)", got, ok, anchor)
	}
}

func TestFindPassThroughConstructorTargetRejectsTailCallB(t *testing.T) {
	start := uint64(0x5400)
	target := uint64(0x5500)
	data := wordsToBytes(
		0xd503237f,
		0xd503201f,
		encodeB(start+8, target),
	)
	if _, ok := findPassThroughConstructorTarget(start, data, uint64Set{target: {}}); ok {
		t.Fatal("findPassThroughConstructorTarget unexpectedly accepted tail-call B")
	}
}

func TestRawWordReferencesAddressWithNilResolveAvoidsLoadResolution(t *testing.T) {
	start := uint64(0x6000)
	loadAddr := uint64(0x6800)
	callTarget := uint64(0x7100)
	data := wordsToBytes(
		encodeADRP(start, loadAddr, 16),
		encodeLDRUOff(16, 1, loadAddr-(loadAddr&^0xfff)),
		encodeBL(start+8, callTarget),
	)
	if rawWordReferencesAddress(start, data, uint64(0x7000), nil) {
		t.Fatal("rawWordReferencesAddress unexpectedly matched target without resolve callback")
	}
}
