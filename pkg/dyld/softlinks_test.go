package dyld

import (
	"errors"
	"testing"

	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/ipsw/pkg/xref"
)

func TestFallbackImportedSymbolNameOnlyTrimsJumpPrefix(t *testing.T) {
	t.Parallel()

	if got := fallbackImportedSymbolName("j__dispatch_once"); got != "_dispatch_once" {
		t.Fatalf("fallback import=%q, want _dispatch_once", got)
	}
}

func TestSoftLinkRecordsFromSymbols(t *testing.T) {
	records := softLinkRecordsFromSymbols("/System/Library/Frameworks/WebCore.framework/WebCore", []softLinkSymbol{
		{Name: "WebCore::softLinkCoreGraphicsCGColorCreateSRGB", Address: 0x1000},
		{Name: "WebCore::initCoreGraphicsCGColorCreateSRGB()", Address: 0x2000},
		{Name: "WebCore::initCoreGraphicsCGColorCreateSRGB()::once", Address: 0x3000},
		{Name: "WebCore::softLinkCoreGraphicsLibrary()", Address: 0x4000},
		{Name: "WebCore::softLinkCoreGraphicsLibrary", Address: 0x5000},
	})
	if len(records) != 1 {
		t.Fatalf("records=%d, want 1: %+v", len(records), records)
	}
	record := records[0]
	if record.Symbol != "CoreGraphicsCGColorCreateSRGB" {
		t.Fatalf("Symbol=%q, want CoreGraphicsCGColorCreateSRGB", record.Symbol)
	}
	if record.GlobalAddr != 0x1000 || record.InitFuncAddr != 0x2000 || record.OnceAddr != 0x3000 || record.FrameworkLibAddr != 0x4000 {
		t.Fatalf("unexpected addresses: %+v", record)
	}
}

func TestSoftLinkGlobalSuffixSkipsLibraryGlobal(t *testing.T) {
	if suffix, ok := softLinkGlobalSuffix("WebCore::softLinkCoreGraphicsLibrary"); ok {
		t.Fatalf("softLink*Library should be a helper, got suffix %q", suffix)
	}
	suffix, ok := softLinkGlobalSuffix("WebCore::softLinkSecuritySecTrustEvaluateWithError")
	if !ok || suffix != "SecuritySecTrustEvaluateWithError" {
		t.Fatalf("suffix=(%q,%t), want SecuritySecTrustEvaluateWithError,true", suffix, ok)
	}
}

func TestFilterSoftLinkRecords(t *testing.T) {
	filter, err := compileSoftLinkFilter("JPEG|dispatch_once")
	if err != nil {
		t.Fatal(err)
	}
	records := filterSoftLinkRecords([]SoftLinkRecord{
		{Symbol: "CoreGraphicsCGColorCreateSRGB"},
		{Symbol: "ImageIOCGImageSourceCreate", OnceName: "dispatch_once_ImageIO"},
		{Symbol: "JPEGDecode"},
	}, filter)
	if len(records) != 2 {
		t.Fatalf("records=%d, want 2: %+v", len(records), records)
	}
	if records[0].Symbol != "ImageIOCGImageSourceCreate" || records[1].Symbol != "JPEGDecode" {
		t.Fatalf("unexpected records: %+v", records)
	}
}

func TestMergeSoftLinkRecordsCoalescesSameGlobal(t *testing.T) {
	t.Parallel()

	records := mergeSoftLinkRecords(
		[]SoftLinkRecord{{Symbol: "AudioToolboxAudioConverterNew", GlobalAddr: 0x6000, GlobalName: "PAL::softLinkAudioToolboxAudioConverterNew"}},
		[]SoftLinkRecord{{Symbol: "AudioConverterNew", GlobalAddr: 0x6000, InitFuncAddr: 0x1000}},
	)
	if len(records) != 1 {
		t.Fatalf("records=%d, want 1: %+v", len(records), records)
	}
	if records[0].Symbol != "AudioToolboxAudioConverterNew" || records[0].InitFuncAddr != 0x1000 {
		t.Fatalf("unexpected merged record: %+v", records[0])
	}
}

func TestSoftLinkRecordsFromInstructionFunctions(t *testing.T) {
	t.Parallel()

	targets := softLinkCallTargets{
		dlsym:        xref.NewTargetSet(0x9000),
		dispatchOnce: xref.NewTargetSet(0x9010),
	}
	funcs := []softLinkFunction{
		{
			start: 0x1000,
			end:   0x1018,
			instrs: []xref.Instruction{
				softLinkTestInst(0x1000, disassemble.ARM64_BL, softLinkTestLabel(0x7000)),
				softLinkTestInst(0x1004, disassemble.ARM64_ADRP, softLinkTestReg(disassemble.REG_X1), softLinkTestImm(0x5000)),
				softLinkTestInst(0x1008, disassemble.ARM64_ADD, softLinkTestReg(disassemble.REG_X1), softLinkTestReg(disassemble.REG_X1), softLinkTestImm(0)),
				softLinkTestInst(0x100c, disassemble.ARM64_BL, softLinkTestLabel(0x9000)),
				softLinkTestInst(0x1010, disassemble.ARM64_ADRP, softLinkTestReg(disassemble.REG_X8), softLinkTestImm(0x6000)),
				softLinkTestInst(0x1014, disassemble.ARM64_STR, softLinkTestReg(disassemble.REG_X0), softLinkTestMem(disassemble.REG_X8, 0)),
			},
		},
		{
			start: 0x2000,
			end:   0x2014,
			instrs: []xref.Instruction{
				softLinkTestInst(0x2000, disassemble.ARM64_ADRP, softLinkTestReg(disassemble.REG_X0), softLinkTestImm(0x8000)),
				softLinkTestInst(0x2004, disassemble.ARM64_ADD, softLinkTestReg(disassemble.REG_X0), softLinkTestReg(disassemble.REG_X0), softLinkTestImm(0)),
				softLinkTestInst(0x2008, disassemble.ARM64_ADRP, softLinkTestReg(disassemble.REG_X1), softLinkTestImm(0x1000)),
				softLinkTestInst(0x200c, disassemble.ARM64_ADD, softLinkTestReg(disassemble.REG_X1), softLinkTestReg(disassemble.REG_X1), softLinkTestImm(0)),
				softLinkTestInst(0x2010, disassemble.ARM64_BL, softLinkTestLabel(0x9010)),
			},
		},
	}
	records := softLinkRecordsFromInstructionFunctions(
		"/System/Library/Frameworks/WebCore.framework/WebCore",
		funcs,
		targets,
		func(addr uint64) (string, error) {
			if addr == 0x5000 {
				return "CGColorCreateSRGB", nil
			}
			return "", errors.New("missing cstring")
		},
		nil,
	)
	if len(records) != 1 {
		t.Fatalf("records=%d, want 1: %+v", len(records), records)
	}
	record := records[0]
	if record.Symbol != "CGColorCreateSRGB" {
		t.Fatalf("Symbol=%q, want CGColorCreateSRGB", record.Symbol)
	}
	if record.InitFuncAddr != 0x1000 || record.GlobalAddr != 0x6000 || record.FrameworkLibAddr != 0x7000 || record.OnceAddr != 0x8000 {
		t.Fatalf("unexpected disassembly record: %+v", record)
	}
}

func softLinkTestInst(addr uint64, op disassemble.Operation, operands ...disassemble.Op) xref.Instruction {
	inst := disassemble.Inst{Address: addr, Operation: op, NumOps: uint8(len(operands))}
	for idx, operand := range operands {
		inst.Operands[idx] = operand
	}
	return xref.Instruction{Inst: inst}
}

func softLinkTestReg(reg disassemble.Register) disassemble.Op {
	var op disassemble.Op
	op.NumRegisters = 1
	op.Registers[0] = reg
	return op
}

func softLinkTestImm(imm uint64) disassemble.Op {
	return disassemble.Op{Class: disassemble.IMM64, Immediate: imm}
}

func softLinkTestLabel(addr uint64) disassemble.Op {
	return disassemble.Op{Class: disassemble.LABEL, Immediate: addr}
}

func softLinkTestMem(base disassemble.Register, offset uint64) disassemble.Op {
	op := disassemble.Op{Class: disassemble.MEM_OFFSET, Immediate: offset}
	op.NumRegisters = 1
	op.Registers[0] = base
	return op
}
