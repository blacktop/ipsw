package nsxpc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/go-macho/types/objc"
)

type mockMemory struct {
	ptrs      map[uint64]uint64
	raws      map[uint64]uint64
	strs      map[uint64]string
	classes   map[uint64]string
	protocols map[uint64]string
}

func (m mockMemory) ReadPointer(addr uint64) (uint64, error) {
	ptr, ok := m.ptrs[addr]
	if !ok {
		return 0, fmt.Errorf("no pointer at %#x", addr)
	}
	return ptr, nil
}

func (m mockMemory) ReadUint64(addr uint64) (uint64, error) {
	raw, ok := m.raws[addr]
	if ok {
		return raw, nil
	}
	ptr, ok := m.ptrs[addr]
	if !ok {
		return 0, fmt.Errorf("no uint64 at %#x", addr)
	}
	return ptr, nil
}

func (m mockMemory) ReadCString(addr uint64) (string, error) {
	str, ok := m.strs[addr]
	if !ok {
		return "", fmt.Errorf("no cstring at %#x", addr)
	}
	return str, nil
}

func (m mockMemory) ClassName(addr uint64) (string, bool) {
	name, ok := m.classes[addr]
	return name, ok
}

func (m mockMemory) ClassPointerName(addr uint64) (string, bool) {
	return m.ClassName(addr)
}

func (m mockMemory) ProtocolName(addr uint64) (string, bool) {
	name, ok := m.protocols[addr]
	return name, ok
}

func TestScanFunctionResolvesInterfaceWithProtocol(t *testing.T) {
	base := uint64(0x100000000)
	stub := uint64(0x100010000)
	protoRef := uint64(0x100002000)
	protoPtr := uint64(0x100003000)
	data := words(
		encADRP(2, base, protoRef),
		encLDRUnsigned(2, 2, protoRef&0xfff),
		encBL(base+8, stub),
	)

	records := scanFunction(functionScan{
		image: "/System/Library/Frameworks/Foundation.framework/Foundation",
		data:  data,
		start: base,
		targets: map[uint64][]targetSpec{
			stub: {{Kind: targetObjCMessage, Selector: selInterfaceWithProtocol}},
		},
		mem: mockMemory{
			ptrs:      map[uint64]uint64{protoRef: protoPtr},
			protocols: map[uint64]string{protoPtr: "NSFileProviderServiceSource"},
		},
	})

	if len(records) != 1 {
		t.Fatalf("records=%d, want 1", len(records))
	}
	if records[0].Kind != KindInterface || !records[0].Resolved || records[0].Protocol != "NSFileProviderServiceSource" {
		t.Fatalf("unexpected record: %#v", records[0])
	}
}

func TestScanFunctionTracksInterfaceAndClassSetReturns(t *testing.T) {
	base := uint64(0x100000000)
	interfaceStub := uint64(0x100010000)
	setObjectsStub := uint64(0x100011000)
	setClassesStub := uint64(0x100012000)
	protoRef := uint64(0x100002000)
	protoPtr := uint64(0x100003000)
	classRefOne := uint64(0x100004000)
	classRefTwo := uint64(0x100004008)
	classOne := uint64(0x100005000)
	classTwo := uint64(0x100006000)
	selRef := uint64(0x100007000)
	selStr := uint64(0x100008000)

	data := words(
		encADRP(2, base, protoRef),
		encLDRUnsigned(2, 2, protoRef&0xfff),
		encBL(base+8, interfaceStub),
		encMOVReg(19, 0),
		encADRP(2, base+16, classRefOne),
		encLDRUnsigned(2, 2, classRefOne&0xfff),
		encADRP(3, base+24, classRefTwo),
		encLDRUnsigned(3, 3, classRefTwo&0xfff),
		encMOVZ(4, 0),
		encBL(base+36, setObjectsStub),
		encMOVReg(20, 0),
		encMOVReg(0, 19),
		encMOVReg(2, 20),
		encADRP(3, base+48, selRef),
		encLDRUnsigned(3, 3, selRef&0xfff),
		encMOVZ(4, 1),
		encMOVZ(5, 0),
		encBL(base+68, setClassesStub),
	)

	records := scanFunction(functionScan{
		image: "/System/Library/PrivateFrameworks/Test.framework/Test",
		data:  data,
		start: base,
		targets: map[uint64][]targetSpec{
			interfaceStub:  {{Kind: targetObjCMessage, Selector: selInterfaceWithProtocol}},
			setObjectsStub: {{Kind: targetObjCMessage, Selector: selSetWithObjects}},
			setClassesStub: {{Kind: targetObjCMessage, Selector: selSetClasses}},
		},
		mem: mockMemory{
			ptrs: map[uint64]uint64{
				protoRef:    protoPtr,
				classRefOne: classOne,
				classRefTwo: classTwo,
				selRef:      selStr,
			},
			strs:      map[uint64]string{selStr: "doThing:"},
			classes:   map[uint64]string{classOne: "NSData", classTwo: "NSString"},
			protocols: map[uint64]string{protoPtr: "TestXPCProtocol"},
		},
	})

	var got Record
	for _, rec := range records {
		if rec.Kind == KindInterfaceClasses {
			got = rec
			break
		}
	}
	if got.Kind == "" {
		t.Fatalf("interface_classes record not found in %#v", records)
	}
	if !got.Resolved || got.Protocol != "TestXPCProtocol" || got.Selector != "doThing:" || got.ArgIndex != 1 || got.OfReply {
		t.Fatalf("unexpected record: %#v", got)
	}
	if strings.Join(got.Classes, ",") != "NSData,NSString" {
		t.Fatalf("classes=%#v", got.Classes)
	}
}

func TestClassSetWithoutRegisterTerminatorIsUnresolved(t *testing.T) {
	var state [31]regValue
	for idx, className := range []string{"NSArray", "NSData", "NSDate", "NSDictionary", "NSSet", "NSString"} {
		state[idx+2] = regValue{kind: valueClass, text: className}
	}

	classSet, ok := returnValueForTarget(
		targetSpec{Kind: targetObjCMessage, Selector: selSetWithObjects},
		state,
		mockMemory{},
	)
	if !ok {
		t.Fatal("setWithObjects return value was not resolved")
	}

	state = [31]regValue{
		0: {kind: valueInterface, protocol: "TestXPCProtocol"},
		2: classSet,
		3: {kind: valueString, text: "doThing:"},
		4: {kind: valueImm, addr: 1},
		5: {kind: valueImm, addr: 0},
	}
	records := recordsForTarget(
		functionScan{image: "/System/Library/PrivateFrameworks/Test.framework/Test", mem: mockMemory{}},
		targetSpec{Kind: targetObjCMessage, Selector: selSetClasses},
		0x1000,
		state,
	)

	if len(records) != 1 {
		t.Fatalf("records=%d, want 1", len(records))
	}
	got := records[0]
	if got.Resolved {
		t.Fatalf("record should be unresolved without a nil terminator: %#v", got)
	}
	if got.Extra["slice_notes"] != "truncated" {
		t.Fatalf("slice_notes=%q, want truncated", got.Extra["slice_notes"])
	}
	if strings.Join(got.Classes, ",") != "NSArray,NSData,NSDate,NSDictionary,NSSet,NSString" {
		t.Fatalf("classes=%#v", got.Classes)
	}
}

func TestSetClassesUnknownInterfaceIsUnresolved(t *testing.T) {
	state := [31]regValue{
		0: {kind: valueParam, note: "param"},
		2: {kind: valueClasses, items: []string{"NSData"}},
		3: {kind: valueString, text: "doThing:"},
		4: {kind: valueImm, addr: 1},
		5: {kind: valueImm, addr: 0},
	}

	records := recordsForTarget(
		functionScan{image: "/System/Library/PrivateFrameworks/Test.framework/Test", mem: mockMemory{}},
		targetSpec{Kind: targetObjCMessage, Selector: selSetClasses},
		0x1000,
		state,
	)

	if len(records) != 1 {
		t.Fatalf("records=%d, want 1", len(records))
	}
	got := records[0]
	if got.Resolved {
		t.Fatalf("record should be unresolved without a protocol-bound interface: %#v", got)
	}
	if got.Protocol != "" {
		t.Fatalf("protocol=%q, want empty", got.Protocol)
	}
	if got.Extra["slice_notes"] != "param" {
		t.Fatalf("slice_notes=%q, want param", got.Extra["slice_notes"])
	}
}

func TestMoveFromZeroRegisterSetsImmediateZero(t *testing.T) {
	state := make([]regValue, 31)

	applyInstruction(nsxpcTestInst(0x1000, disassemble.ARM64_MOV,
		disassemble.Operand{Registers: []disassemble.Register{disassemble.REG_X5}},
		disassemble.Operand{Registers: []disassemble.Register{disassemble.REG_XZR}},
	), state, nil, mockMemory{})

	if got := state[5]; got.kind != valueImm || got.addr != 0 {
		t.Fatalf("x5=%#v, want immediate zero", got)
	}
}

func TestIndexedLoadDoesNotResolveBaseAsZeroOffset(t *testing.T) {
	state := make([]regValue, 31)
	state[1] = regValue{kind: valueAddr, addr: 0x1000}
	state[2] = regValue{kind: valueImm, addr: 0x20}

	applyInstruction(nsxpcTestInst(0x1000, disassemble.ARM64_LDR,
		disassemble.Operand{Registers: []disassemble.Register{disassemble.REG_X0}},
		disassemble.Operand{Class: disassemble.MEM_REG, Registers: []disassemble.Register{disassemble.REG_X1, disassemble.REG_X2}},
	), state, nil, mockMemory{
		classes: map[uint64]string{0x1000: "WrongClass"},
	})

	if got := state[0]; got.kind != valueUnknown || got.note != "indirect" {
		t.Fatalf("x0=%#v, want indirect unknown", got)
	}
}

func TestScanFunctionSecureCodingDecode(t *testing.T) {
	base := uint64(0x100000000)
	stub := uint64(0x100010000)
	classRef := uint64(0x100002000)
	classPtr := uint64(0x100003000)
	keyAddr := uint64(0x100004000)
	data := words(
		encADRP(2, base, classRef),
		encLDRUnsigned(2, 2, classRef&0xfff),
		encADRP(3, base+8, keyAddr),
		encADDImm(3, 3, keyAddr&0xfff),
		encBL(base+16, stub),
	)

	records := scanFunction(functionScan{
		image:      "/System/Library/PrivateFrameworks/Test.framework/Test",
		classNames: []string{"TestModel"},
		data:       data,
		start:      base,
		secureOnly: true,
		targets: map[uint64][]targetSpec{
			stub: {{Kind: targetObjCMessage, Selector: selDecodeObjectOfClass}},
		},
		mem: mockMemory{
			ptrs:    map[uint64]uint64{classRef: classPtr},
			strs:    map[uint64]string{keyAddr: "payload"},
			classes: map[uint64]string{classPtr: "NSData"},
		},
	})

	if len(records) != 1 {
		t.Fatalf("records=%d, want 1", len(records))
	}
	if records[0].Kind != KindSecureCodingDecode || !records[0].Resolved || records[0].Class != "TestModel" || records[0].Key != "payload" {
		t.Fatalf("unexpected record: %#v", records[0])
	}
	if strings.Join(records[0].DecodedClasses, ",") != "NSData" {
		t.Fatalf("decoded classes=%#v", records[0].DecodedClasses)
	}
}

func TestScanFunctionTracksObjCOptClassStubReturn(t *testing.T) {
	base := uint64(0x100000000)
	optClassStub := uint64(0x100010000)
	decodeStub := uint64(0x100011000)
	classRef := uint64(0x100002000)
	classPtr := uint64(0x100003000)
	keyAddr := uint64(0x100004000)
	target, ok := matchRuntimeTarget("_objc_opt_class_stub")
	if !ok || target.Kind != targetObjCGetClass {
		t.Fatalf("objc_opt_class_stub target=%#v ok=%t", target, ok)
	}
	data := words(
		encADRP(0, base, classRef),
		encLDRUnsigned(0, 0, classRef&0xfff),
		encBL(base+8, optClassStub),
		encMOVReg(2, 0),
		encADRP(3, base+16, keyAddr),
		encADDImm(3, 3, keyAddr&0xfff),
		encBL(base+24, decodeStub),
	)

	records := scanFunction(functionScan{
		image:      "/System/Library/PrivateFrameworks/Test.framework/Test",
		classNames: []string{"TestModel"},
		data:       data,
		start:      base,
		secureOnly: true,
		targets: map[uint64][]targetSpec{
			optClassStub: {target},
			decodeStub:   {{Kind: targetObjCMessage, Selector: selDecodeObjectOfClass}},
		},
		mem: mockMemory{
			ptrs:    map[uint64]uint64{classRef: classPtr},
			strs:    map[uint64]string{keyAddr: "payload"},
			classes: map[uint64]string{classPtr: "NSData"},
		},
	})
	if len(records) != 1 || !records[0].Resolved || strings.Join(records[0].DecodedClasses, ",") != "NSData" {
		t.Fatalf("unexpected records: %#v", records)
	}
}

func TestScanFunctionPreservesClassReturnForUnindexedHelper(t *testing.T) {
	base := uint64(0x100000000)
	optClassHelper := uint64(0x100010000)
	decodeStub := uint64(0x100011000)
	classRef := uint64(0x100002000)
	classPtr := uint64(0x100003000)
	data := words(
		encADRP(0, base, classRef),
		encLDRUnsigned(0, 0, classRef&0xfff),
		encBL(base+8, optClassHelper),
		encMOVReg(2, 0),
		encBL(base+16, decodeStub),
	)

	records := scanFunction(functionScan{
		image:      "/System/Library/PrivateFrameworks/Test.framework/Test",
		classNames: []string{"TestModel"},
		data:       data,
		start:      base,
		secureOnly: true,
		targets: map[uint64][]targetSpec{
			decodeStub: {{Kind: targetObjCMessage, Selector: selDecodeObjectOfClass}},
		},
		mem: mockMemory{
			ptrs:    map[uint64]uint64{classRef: classPtr},
			classes: map[uint64]string{classPtr: "NSData"},
		},
	})
	if len(records) != 1 || !records[0].Resolved || strings.Join(records[0].DecodedClasses, ",") != "NSData" {
		t.Fatalf("unexpected records: %#v", records)
	}
}

func TestDecodeMethodTypeClasses(t *testing.T) {
	info := decodeMethodTypeClasses(`@"NSData"24@0:8@"NSString"16q24@"NSArray<CKRecord>"32@?40`)
	if info.ReturnClass != "NSData" {
		t.Fatalf("return=%q", info.ReturnClass)
	}
	got := strings.Join(info.ParamClasses, ",")
	if got != "NSString,,NSArray," {
		t.Fatalf("params=%q", got)
	}
}

func TestProtocolMethodRecordsIncludeInheritedProtocols(t *testing.T) {
	s := scanner{
		protocols: map[string]objc.Protocol{
			"Child": {
				Name: "Child",
				InstanceMethods: []objc.Method{
					{Name: "child:", Types: `v24@0:8@"NSString"16`},
				},
				Prots: []objc.Protocol{{Name: "Parent"}, {Name: "Parent"}},
			},
			"Parent": {
				Name: "Parent",
				InstanceMethods: []objc.Method{
					{Name: "parent:", Types: `@"NSData"16@0:8`},
				},
			},
		},
	}

	records := s.protocolMethodRecords(map[string]struct{}{"Child": {}})
	if len(records) != 2 {
		t.Fatalf("records=%d, want 2: %#v", len(records), records)
	}

	bySelector := make(map[string]Record)
	for _, rec := range records {
		bySelector[rec.Selector] = rec
	}
	parent := bySelector["parent:"]
	if parent.Kind != KindProtocolMethod || parent.Protocol != "Child" || !parent.Required || !parent.Instance {
		t.Fatalf("unexpected inherited record: %#v", parent)
	}
	if parent.ReturnClass != "NSData" {
		t.Fatalf("inherited return class=%q, want NSData", parent.ReturnClass)
	}
	if _, ok := bySelector["child:"]; !ok {
		t.Fatalf("child method missing from %#v", records)
	}
}

func TestClassNameFromSymbol(t *testing.T) {
	for _, tt := range []struct {
		sym  string
		want string
	}{
		{"class_NSData", "NSData"},
		{"_ptr.NSString", "NSString"},
		{"_OBJC_CLASS_$_NSArray", "NSArray"},
		{"0x1234 ; UIKit", ""},
		{"objc_retain", ""},
	} {
		if got := classNameFromSymbol(tt.sym); got != tt.want {
			t.Fatalf("classNameFromSymbol(%q)=%q, want %q", tt.sym, got, tt.want)
		}
	}
}

func TestWriteJSONLDeterministic(t *testing.T) {
	records := []Record{
		{Kind: KindSecureCodingDecode, Image: "b", Class: "C", Callsite: "0x9", DecodedClasses: []string{"Z", "A"}, Extra: map[string]string{}},
		{Kind: KindInterface, Image: "a", Callsite: "0x1", Protocol: "P", Resolved: true, Extra: map[string]string{}},
		{Kind: KindInterfaceClasses, Image: "a", Callsite: "0x2", Protocol: "P", Selector: "s:", Classes: []string{"B", "A"}, Extra: map[string]string{"slice_notes": "param"}},
		{Kind: KindProtocolMethod, Protocol: "P", Selector: "m:", Instance: true, Required: true, TypeEncoding: "v16@0:8", ParamClasses: []string{"B", "A"}, Extra: map[string]string{}},
	}
	var first bytes.Buffer
	var second bytes.Buffer
	if err := WriteJSONL(&first, records); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSONL(&second, records); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatalf("not deterministic:\n%s\n%s", first.String(), second.String())
	}
	lines := strings.Split(strings.TrimSpace(first.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("lines=%d", len(lines))
	}
	if !strings.HasPrefix(lines[0], `{"callsite":`) || !strings.Contains(lines[1], `"classes":["A","B"]`) {
		t.Fatalf("unexpected JSONL:\n%s", first.String())
	}
	if !strings.Contains(lines[2], `,"image":"","instance":true,"kind":"protocol_method","param_classes":["B","A"]`) {
		t.Fatalf("protocol_method keys are not sorted or param order changed:\n%s", lines[2])
	}
}

func words(ws ...uint32) []byte {
	var buf bytes.Buffer
	for _, w := range ws {
		_ = binary.Write(&buf, binary.LittleEndian, w)
	}
	return buf.Bytes()
}

func encADRP(rd int, pc, target uint64) uint32 {
	pcPage := pc &^ 0xfff
	targetPage := target &^ 0xfff
	pages := int64(targetPage-pcPage) / 0x1000
	imm := uint32(uint64(pages) & ((1 << 21) - 1))
	immlo := imm & 0x3
	immhi := (imm >> 2) & 0x7ffff
	return 0x90000000 | (immlo << 29) | (immhi << 5) | uint32(rd)
}

func encADDImm(rd, rn int, imm uint64) uint32 {
	return 0x91000000 | (uint32(imm&0xfff) << 10) | (uint32(rn) << 5) | uint32(rd)
}

func encLDRUnsigned(rt, rn int, imm uint64) uint32 {
	return 0xf9400000 | (uint32((imm/8)&0xfff) << 10) | (uint32(rn) << 5) | uint32(rt)
}

func encBL(pc, target uint64) uint32 {
	off := int64(target-pc) / 4
	return 0x94000000 | (uint32(uint64(off)) & 0x03ffffff)
}

func encMOVReg(rd, rm int) uint32 {
	return 0xaa0003e0 | (uint32(rm) << 16) | uint32(rd)
}

func encMOVZ(rd int, imm uint64) uint32 {
	return 0xd2800000 | (uint32(imm&0xffff) << 5) | uint32(rd)
}

func nsxpcTestOp(op disassemble.Operand) disassemble.Op {
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

func nsxpcTestInst(addr uint64, op disassemble.Operation, operands ...disassemble.Operand) *disassemble.Inst {
	inst := &disassemble.Inst{
		Address:   addr,
		Operation: op,
		NumOps:    uint8(len(operands)),
	}
	for idx := range operands {
		inst.Operands[idx] = nsxpcTestOp(operands[idx])
	}
	return inst
}
