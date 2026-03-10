package cpp

import (
	"testing"

	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

func TestTrackStaticValueInstructionRespectsLoadAddrMaterializationOption(t *testing.T) {
	scanner := &Scanner{}
	var regBase [31]uint64
	var regLoadAddr [31]uint64
	var regValue [31]uint64

	regBase[1] = 0x1234
	inst := testInst(0x1000, disassemble.ARM64_LDR,
		disassemble.Operand{Registers: []disassemble.Register{disassemble.REG_X0}},
		disassemble.Operand{Class: disassemble.MEM_OFFSET, Registers: []disassemble.Register{disassemble.REG_X1}, Immediate: 0},
	)

	scanner.trackStaticValueInstruction(nil, &regBase, &regLoadAddr, &regValue, inst, staticValueTrackOptions{
		acceptAnyLoadAddr:      false,
		propagateLoadAddrInAdd: true,
		handleLoadPairs:        true,
	})
	if got, want := regLoadAddr[0], uint64(0x1234); got != want {
		t.Fatalf("regLoadAddr[x0] = %#x, want %#x", got, want)
	}
	if got := regValue[0]; got != 0 {
		t.Fatalf("regValue[x0] = %#x, want 0 when unresolved load addr is not accepted", got)
	}

	regBase = [31]uint64{}
	regLoadAddr = [31]uint64{}
	regValue = [31]uint64{}
	regBase[1] = 0x1234
	scanner.trackStaticValueInstruction(nil, &regBase, &regLoadAddr, &regValue, inst, staticValueTrackOptions{
		acceptAnyLoadAddr:      true,
		propagateLoadAddrInAdd: false,
		handleLoadPairs:        false,
	})
	if got, want := regValue[0], uint64(0x1234); got != want {
		t.Fatalf("regValue[x0] = %#x, want %#x when unresolved load addr is accepted", got, want)
	}
}

func TestTrackStaticValueInstructionRespectsAddLoadAddrPropagationOption(t *testing.T) {
	scanner := &Scanner{}
	inst := testInst(0x2000, disassemble.ARM64_ADD,
		disassemble.Operand{Registers: []disassemble.Register{disassemble.REG_X0}},
		disassemble.Operand{Registers: []disassemble.Register{disassemble.REG_X1}},
		disassemble.Operand{Class: disassemble.IMM64, Immediate: 0x20},
	)

	var regBase [31]uint64
	var regLoadAddr [31]uint64
	var regValue [31]uint64
	regLoadAddr[1] = 0x2000

	scanner.trackStaticValueInstruction(nil, &regBase, &regLoadAddr, &regValue, inst, staticValueTrackOptions{
		acceptAnyLoadAddr:      true,
		propagateLoadAddrInAdd: false,
		handleLoadPairs:        false,
	})
	if got := regLoadAddr[0]; got != 0 {
		t.Fatalf("regLoadAddr[x0] = %#x, want 0 when ADD should not propagate load addresses", got)
	}

	regBase = [31]uint64{}
	regLoadAddr = [31]uint64{}
	regValue = [31]uint64{}
	regLoadAddr[1] = 0x2000
	scanner.trackStaticValueInstruction(nil, &regBase, &regLoadAddr, &regValue, inst, staticValueTrackOptions{
		acceptAnyLoadAddr:      false,
		propagateLoadAddrInAdd: true,
		handleLoadPairs:        true,
	})
	if got, want := regLoadAddr[0], uint64(0x2020); got != want {
		t.Fatalf("regLoadAddr[x0] = %#x, want %#x when ADD should propagate load addresses", got, want)
	}
}

func TestPointerCacheCoversAddressSkipsTextAndBSS(t *testing.T) {
	m := &macho.File{}
	m.Sections = []*types.Section{
		{SectionHeader: types.SectionHeader{Name: "__text", Seg: "__TEXT", Addr: 0x1000, Size: 0x100}},
		{SectionHeader: types.SectionHeader{Name: "__data", Seg: "__DATA_CONST", Addr: 0x2000, Size: 0x100}},
		{SectionHeader: types.SectionHeader{Name: "entry.__bss", Seg: "__DATA", Addr: 0x3000, Size: 0x100}},
	}

	if pointerCacheCoversAddress(m, 0x1010) {
		t.Fatal("pointer cache should not claim __TEXT literal addresses")
	}
	if !pointerCacheCoversAddress(m, 0x2010) {
		t.Fatal("pointer cache should cover DATA section addresses")
	}
	if pointerCacheCoversAddress(m, 0x3010) {
		t.Fatal("pointer cache should not claim __bss addresses")
	}
}

func TestTrackRegisterRawHandles32BitMovWideAliases(t *testing.T) {
	scanner := &Scanner{}
	var regBase [31]uint64
	var regValue [31]uint64

	regBase[3] = 0xffff_fe00_0000_0000
	regValue[3] = 0xffff_fe00_0000_0000

	trackRegisterRaw(scanner, nil, 0x52800803, 0x1000, &regBase, &regValue) // movz w3, #0x40
	if got, want := regValue[3], uint64(0x40); got != want {
		t.Fatalf("regValue[w3] after movz = %#x, want %#x", got, want)
	}
	if got := regBase[3]; got != 0 {
		t.Fatalf("regBase[w3] after movz = %#x, want 0", got)
	}

	trackRegisterRaw(scanner, nil, 0x72a00023, 0x1004, &regBase, &regValue) // movk w3, #0x1, lsl #16
	if got, want := regValue[3], uint64(0x0001_0040); got != want {
		t.Fatalf("regValue[w3] after movk = %#x, want %#x", got, want)
	}
}
