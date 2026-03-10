package cpp

import (
	"encoding/binary"
	"testing"
)

func encodeB(from, to uint64) uint32 {
	imm := int64(to-from) >> 2
	return 0x14000000 | uint32(imm)&0x03ffffff
}

func encodeBL(from, to uint64) uint32 {
	imm := int64(to-from) >> 2
	return 0x94000000 | uint32(imm)&0x03ffffff
}

func wordsToBytes(words ...uint32) []byte {
	out := make([]byte, 4*len(words))
	for i, word := range words {
		binary.LittleEndian.PutUint32(out[i*4:], word)
	}
	return out
}

func TestFindFunctionStartInSection(t *testing.T) {
	base := uint64(0x1000)
	data := wordsToBytes(
		0xd503237f,
		0xd503201f,
		0xd503201f,
		0xd503237f,
		0xd503201f,
	)

	start, err := findFunctionStartInSection(base, data, base+0x10)
	if err != nil {
		t.Fatalf("findFunctionStartInSection failed: %v", err)
	}
	if want := base + 0x0c; start != want {
		t.Fatalf("findFunctionStartInSection = %#x, want %#x", start, want)
	}
}

func TestInspectFunctionDataDirectCall(t *testing.T) {
	start := uint64(0x2000)
	anchor := uint64(0x2100)
	data := wordsToBytes(
		encodeBL(start, anchor),
		0xd503201f,
	)

	inspection := inspectFunctionData(start, data, func(addr uint64) bool {
		return addr == anchor
	})
	if !inspection.direct {
		t.Fatalf("expected direct OSMetaClass caller")
	}
	if len(inspection.nextTargets) != 0 {
		t.Fatalf("unexpected wrapper targets: %v", inspection.nextTargets)
	}
}

func TestInspectFunctionDataWrapperTargets(t *testing.T) {
	start := uint64(0x3000)
	targetA := uint64(0x3040)
	targetB := uint64(0x3080)
	data := wordsToBytes(
		encodeB(start, targetA),
		encodeBL(start+4, targetB),
		0xd503201f,
	)

	inspection := inspectFunctionData(start, data, func(uint64) bool { return false })
	if inspection.direct {
		t.Fatalf("expected wrapper inspection, not direct")
	}
	if got, want := len(inspection.nextTargets), 2; got != want {
		t.Fatalf("wrapper targets = %d, want %d (%v)", got, want, inspection.nextTargets)
	}
	if inspection.nextTargets[0] != targetA || inspection.nextTargets[1] != targetB {
		t.Fatalf("wrapper targets = %#v, want [%#x %#x]", inspection.nextTargets, targetA, targetB)
	}
}
