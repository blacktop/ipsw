package iokit

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/pkg/kernelcache/cpp"
)

func TestWriteJSONLMethodRecordUsesStableSortedKeys(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	err := WriteJSONL(&out, []Record{
		{
			Kind:              KindMethod,
			Class:             "ExampleUserClient",
			Bundle:            "com.apple.example",
			Selector:          2,
			MethodAddr:        "0xfffffe0000001000",
			MethodSymbol:      "ExampleUserClient::method",
			DispatchKind:      DispatchExternalMethod,
			ScalarInputCount:  1,
			ScalarOutputCount: 2,
			StructInputSize:   3,
			StructOutputSize:  4,
			Flags:             0,
			Resolved:          true,
			Extra:             map[string]string{},
		},
	})
	if err != nil {
		t.Fatalf("WriteJSONL failed: %v", err)
	}

	got := strings.TrimSpace(out.String())
	want := `{"bundle":"com.apple.example","class":"ExampleUserClient","dispatch_kind":"IOExternalMethodDispatch","extra":{},"flags":0,"kind":"iokit_method","method_addr":"0xfffffe0000001000","method_symbol":"ExampleUserClient::method","resolved":true,"scalar_input_count":1,"scalar_output_count":2,"selector":2,"struct_input_size":3,"struct_output_size":4}`
	if got != want {
		t.Fatalf("jsonl = %s, want %s", got, want)
	}
}

func TestWriteJSONLSortsByContractKey(t *testing.T) {
	t.Parallel()

	records := []Record{
		{Kind: KindMethod, Bundle: "b", Class: "B", Selector: 1, MethodAddr: "0x2", DispatchKind: DispatchUnknown, Extra: map[string]string{}},
		{Kind: KindMethod, Bundle: "a", Class: "A", Selector: 1, MethodAddr: "0x2", DispatchKind: DispatchUnknown, Extra: map[string]string{}},
		{Kind: KindMethod, Bundle: "a", Class: "A", Selector: 0, MethodAddr: "0x1", DispatchKind: DispatchUnknown, Extra: map[string]string{}},
	}

	SortRecords(records)
	if records[0].Bundle != "a" || records[0].Selector != 0 {
		t.Fatalf("first record after sort = %+v", records[0])
	}
	if records[1].Bundle != "a" || records[1].Selector != 1 {
		t.Fatalf("second record after sort = %+v", records[1])
	}
	if records[2].Bundle != "b" {
		t.Fatalf("third record after sort = %+v", records[2])
	}
}

func TestReachesClassFollowsSuperIndex(t *testing.T) {
	t.Parallel()

	classes := []cpp.Class{
		{Name: "OSObject", SuperIndex: -1},
		{Name: "IOService", SuperIndex: 0},
		{Name: "IOUserClient", SuperIndex: 1},
		{Name: "ExampleUserClient", SuperIndex: 2},
	}
	if !reachesClass(classes, 3, "IOUserClient") {
		t.Fatal("expected ExampleUserClient to reach IOUserClient")
	}
	if !reachesClass(classes, 3, "IOService") {
		t.Fatal("expected ExampleUserClient to reach IOService")
	}
	if reachesClass(classes, 1, "IOUserClient") {
		t.Fatal("IOService should not reach IOUserClient")
	}
}

func TestCombineExprPreservesAlternateBases(t *testing.T) {
	t.Parallel()

	got := combineExpr(
		linearExpr{valid: true, base: 0x1000, alts: []uint64{0x2000, 0x1000}},
		linearExpr{valid: true, base: 0x80, coeff: dispatchSize2022},
	)
	bases := exprBases(got)
	want := []uint64{0x1080, 0x2080}
	if got.coeff != dispatchSize2022 {
		t.Fatalf("coeff = %#x, want %#x", got.coeff, dispatchSize2022)
	}
	assertUint64sEqual(t, bases, want)
}

func TestAddImmediateExprDoesNotMutateSourceAlternates(t *testing.T) {
	t.Parallel()

	src := linearExpr{valid: true, base: 0x1000, alts: []uint64{0x2000, 0x1000}}
	got := addImmediateExpr(src, 0x80)

	if src.base != 0x1000 {
		t.Fatalf("source base mutated to %#x", src.base)
	}
	wantSrc := []uint64{0x2000, 0x1000}
	for idx := range wantSrc {
		if src.alts[idx] != wantSrc[idx] {
			t.Fatalf("source alts mutated to %#v", src.alts)
		}
	}
	assertUint64sEqual(t, exprBases(got), []uint64{0x1080, 0x2080})
}

func TestTiedDispatchStrideUses2022EvidenceBeforeClassicHint(t *testing.T) {
	t.Parallel()

	stride, kind, ok := tiedDispatchStride(DispatchExternalMethod, true)
	if !ok {
		t.Fatal("expected tie to resolve")
	}
	if stride != dispatchSize2022 || kind != DispatchExternalMethod2022 {
		t.Fatalf("tie resolved to %s/%d, want %s/%d", kind, stride, DispatchExternalMethod2022, dispatchSize2022)
	}
}

func TestSelectedDispatchAnalysisClonesEntriesAndPreservesKind(t *testing.T) {
	t.Parallel()

	entries := map[int]uint64{263: 0x1000}
	analysis, ok := selectedDispatchAnalysis(0x2000, nil, entries, DispatchExternalMethod2022)
	if ok {
		t.Fatal("selectedDispatchAnalysis unexpectedly accepted nil owner")
	}
	analysis, ok = selectedDispatchAnalysis(0x2000, &macho.File{}, entries, DispatchExternalMethod2022)
	if !ok {
		t.Fatal("selectedDispatchAnalysis failed")
	}
	entries[263] = 0x3000
	if analysis.kind != DispatchExternalMethod2022 || analysis.stride != dispatchSize2022 {
		t.Fatalf("analysis kind/stride=(%s,%d), want (%s,%d)", analysis.kind, analysis.stride, DispatchExternalMethod2022, dispatchSize2022)
	}
	if analysis.selectedEntries[263] != 0x1000 {
		t.Fatalf("selected entry=%#x, want cloned original 0x1000", analysis.selectedEntries[263])
	}
}

func TestNormalizeMaxInstructionCapsUsesSwitchDefaultOnlyForDefaultCap(t *testing.T) {
	t.Parallel()

	maxInst, maxSwitchInst := normalizeMaxInstructionCaps(0)
	if maxInst != defaultMaxFunctionInstructions {
		t.Fatalf("maxInst=%d, want %d", maxInst, defaultMaxFunctionInstructions)
	}
	if maxSwitchInst != defaultSwitchMaxFunctionInstructions {
		t.Fatalf("maxSwitchInst=%d, want %d", maxSwitchInst, defaultSwitchMaxFunctionInstructions)
	}
}

func TestNormalizeMaxInstructionCapsHonorsExplicitCap(t *testing.T) {
	t.Parallel()

	maxInst, maxSwitchInst := normalizeMaxInstructionCaps(128)
	if maxInst != 128 || maxSwitchInst != 128 {
		t.Fatalf("caps=(%d,%d), want (128,128)", maxInst, maxSwitchInst)
	}
}

func TestFilterRecordsByClassMatchesMethodAndServiceClasses(t *testing.T) {
	t.Parallel()

	filter, err := compileClassFilter("Surface|Audio")
	if err != nil {
		t.Fatalf("compileClassFilter failed: %v", err)
	}
	records := []Record{
		{Kind: KindMethod, Class: "IOSurfaceRootUserClient"},
		{Kind: KindServiceClient, ServiceClass: "IOAudioEngine", UserClientClass: "IOAudioEngineUserClient"},
		{Kind: KindMethod, Class: "UnrelatedUserClient"},
	}

	got := filterRecordsByClass(records, filter)
	if len(got) != 2 {
		t.Fatalf("filtered records=%#v, want two", got)
	}
	if got[0].Class != "IOSurfaceRootUserClient" {
		t.Fatalf("first filtered record=%#v", got[0])
	}
	if got[1].ServiceClass != "IOAudioEngine" {
		t.Fatalf("second filtered record=%#v", got[1])
	}
}

func TestConditionalDispatchTablesKeepBothBasesAndTags(t *testing.T) {
	t.Parallel()

	analysis := methodAnalysis{
		note:       "conditional_array",
		arrayBase:  0x1000,
		arrayBases: []uint64{0x1000, 0x2000},
	}
	bases := dispatchTableBases(analysis)
	assertUint64sEqual(t, bases, []uint64{0x1000, 0x2000})

	extra := map[string]string{}
	addConditionalTableExtra(extra, 1, bases[1])
	if extra["table"] != "table_1" {
		t.Fatalf("table tag=%q, want table_1", extra["table"])
	}
	if extra["table_base"] != "0x2000" {
		t.Fatalf("table_base=%q, want 0x2000", extra["table_base"])
	}
	if extra["slice_notes"] != "conditional_array" {
		t.Fatalf("slice_notes=%q, want conditional_array", extra["slice_notes"])
	}
}

func TestDispatchAnalysisPreservesScaledConditionalArrayBases(t *testing.T) {
	t.Parallel()

	analysis, ok := (&analyzer{}).dispatchAnalysisFromExpr(
		0x3000,
		&macho.File{},
		linearExpr{valid: true, base: 0x1000, coeff: dispatchSizeClassic, alts: []uint64{0x1000, 0x2000}},
		linearExpr{},
		2,
		DispatchExternalMethod,
	)
	if !ok {
		t.Fatal("dispatchAnalysisFromExpr rejected scaled conditional array")
	}
	if analysis.note != "conditional_array" {
		t.Fatalf("note=%q, want conditional_array", analysis.note)
	}
	assertUint64sEqual(t, analysis.arrayBases, []uint64{0x1000, 0x2000})
}

func TestApplyMultiplyTracksSelectorStride(t *testing.T) {
	t.Parallel()

	regs := make([]linearExpr, 31)
	regs[1] = linearExpr{valid: true, coeff: 1}
	regs[9] = linearExpr{valid: true, base: dispatchSizeClassic}
	inst := disassemble.Inst{Operation: disassemble.ARM64_UMULL, NumOps: 3}
	inst.Operands[0].NumRegisters = 1
	inst.Operands[0].Registers[0] = disassemble.REG_X9
	inst.Operands[1].NumRegisters = 1
	inst.Operands[1].Registers[0] = disassemble.REG_W1
	inst.Operands[2].NumRegisters = 1
	inst.Operands[2].Registers[0] = disassemble.REG_W9

	applyMultiply(&inst, regs)
	if !regs[9].valid || regs[9].base != 0 || regs[9].coeff != dispatchSizeClassic {
		t.Fatalf("scaled selector expr=%+v, want coeff %#x", regs[9], dispatchSizeClassic)
	}
}

func assertUint64sEqual(t *testing.T, got []uint64, want []uint64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	for idx := range want {
		if got[idx] != want[idx] {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}
}

func TestSwitchAnalysisInstructionsUsesSwitchDecodeCap(t *testing.T) {
	t.Parallel()

	const nop = uint32(0xd503201f)
	data := make([]byte, (defaultMaxFunctionInstructions+20)*4)
	for off := 0; off < len(data); off += 4 {
		binary.LittleEndian.PutUint32(data[off:], nop)
	}
	a := &analyzer{
		maxInst:       defaultMaxFunctionInstructions,
		maxSwitchInst: defaultMaxFunctionInstructions + 20,
	}
	instrs := decodeInstructions(data, 0x1000, a.maxInst)
	if len(instrs) != defaultMaxFunctionInstructions {
		t.Fatalf("initial decode length=%d, want %d", len(instrs), defaultMaxFunctionInstructions)
	}
	got := a.switchAnalysisInstructions(data, 0x1000, instrs)
	if len(got) != defaultMaxFunctionInstructions+20 {
		t.Fatalf("switch decode length=%d, want %d", len(got), defaultMaxFunctionInstructions+20)
	}
}

func TestSwitchJumpTargetAddressHandlesSignedOffsets(t *testing.T) {
	t.Parallel()

	if got, ok := switchJumpTargetAddress(0x1000, 0x40); !ok || got != 0x1040 {
		t.Fatalf("positive jump target=(%#x,%t), want 0x1040,true", got, ok)
	}
	if got, ok := switchJumpTargetAddress(0x1000, -0x40); !ok || got != 0x0fc0 {
		t.Fatalf("negative jump target=(%#x,%t), want 0x0fc0,true", got, ok)
	}
	if _, ok := switchJumpTargetAddress(0x20, -0x40); ok {
		t.Fatal("underflowing negative jump target unexpectedly succeeded")
	}
}

func TestSwitchJumpTableAddRecognizesBasePlusLoadedOffset(t *testing.T) {
	t.Parallel()

	var regs [31]linearExpr
	regs[8] = linearExpr{valid: true, base: 0x1000}
	loads := map[int]uint64{9: 0x1000}
	inst := disassemble.Inst{Operation: disassemble.ARM64_ADD, NumOps: 3}
	inst.Operands[0].NumRegisters = 1
	inst.Operands[0].Registers[0] = disassemble.REG_X10
	inst.Operands[1].NumRegisters = 1
	inst.Operands[1].Registers[0] = disassemble.REG_X8
	inst.Operands[2].NumRegisters = 1
	inst.Operands[2].Registers[0] = disassemble.REG_X9

	reg, base, ok := switchJumpTableAdd(&inst, regs, loads)
	if !ok || reg != 10 || base != 0x1000 {
		t.Fatalf("jump-table add=(reg:%d base:%#x ok:%t), want reg 10 base 0x1000", reg, base, ok)
	}
}

func TestLegacyCountsForFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		flags     int64
		count0    uint64
		count1    uint64
		scalarIn  int64
		scalarOut int64
		structIn  int64
		structOut int64
	}{
		{name: "scalar-scalar", flags: 0, count0: 2, count1: 1, scalarIn: 2, scalarOut: 1},
		{name: "scalar-struct-out", flags: 2, count0: 3, count1: 0xffffffff, scalarIn: 3, structOut: 0xffffffff},
		{name: "struct-struct", flags: 3, count0: 16, count1: 32, structIn: 16, structOut: 32},
		{name: "scalar-struct-in", flags: 4, count0: 1, count1: 64, scalarIn: 1, structIn: 64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			scalarIn, scalarOut, structIn, structOut, note := legacyCountsForFlags(tt.flags, tt.count0, tt.count1)
			if note != "" {
				t.Fatalf("unexpected note %q", note)
			}
			if scalarIn != tt.scalarIn || scalarOut != tt.scalarOut || structIn != tt.structIn || structOut != tt.structOut {
				t.Fatalf("counts=(%d,%d,%d,%d), want (%d,%d,%d,%d)",
					scalarIn, scalarOut, structIn, structOut, tt.scalarIn, tt.scalarOut, tt.structIn, tt.structOut)
			}
		})
	}
}

func TestLegacyCountsForUnknownFlags(t *testing.T) {
	t.Parallel()

	scalarIn, scalarOut, structIn, structOut, note := legacyCountsForFlags(7, 1, 2)
	if note != "legacy_flags_unknown" {
		t.Fatalf("note=%q, want legacy_flags_unknown", note)
	}
	if scalarIn != -1 || scalarOut != -1 || structIn != -1 || structOut != -1 {
		t.Fatalf("counts=(%d,%d,%d,%d), want all -1", scalarIn, scalarOut, structIn, structOut)
	}
}

func TestSwitchRecordsAnnotateStructureInputReads(t *testing.T) {
	t.Parallel()

	analysis := methodAnalysis{
		count: 2,
		switchCases: map[int]switchCaseInfo{
			1: {methodAddr: 0x1000, readsStructureInput: true, readsStructureInputSize: true},
		},
	}
	records := (&analyzer{}).switchRecords(&classInfo{Class: cpp.Class{Name: "SwitchUserClient"}}, analysis)
	if len(records) != 2 {
		t.Fatalf("records=%#v, want two", records)
	}
	if records[0].Extra["reads_structure_input"] != "" {
		t.Fatalf("selector 0 unexpectedly annotated: %#v", records[0].Extra)
	}
	if records[1].Extra["reads_structure_input"] != "true" || records[1].Extra["reads_structure_input_size"] != "true" {
		t.Fatalf("selector 1 annotations=%#v", records[1].Extra)
	}
	if records[1].MethodAddr != "0x1000" || !records[1].Resolved {
		t.Fatalf("selector 1 method=(%s resolved:%t), want 0x1000 resolved", records[1].MethodAddr, records[1].Resolved)
	}
}
