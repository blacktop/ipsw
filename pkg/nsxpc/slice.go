package nsxpc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/ipsw/pkg/disass"
)

const maxSliceInstructions = 32

type memoryReader interface {
	ReadPointer(addr uint64) (uint64, error)
	ReadUint64(addr uint64) (uint64, error)
	ReadCString(addr uint64) (string, error)
	ClassName(addr uint64) (string, bool)
	ClassPointerName(addr uint64) (string, bool)
	ProtocolName(addr uint64) (string, bool)
}

type valueKind uint8

const (
	valueUnknown valueKind = iota
	valueParam
	valueAddr
	valueImm
	valueString
	valueClass
	valueClasses
	valueProtocol
	valueInterface
)

type regValue struct {
	kind     valueKind
	addr     uint64
	text     string
	items    []string
	protocol string
	note     string
}

type decodedInst struct {
	disassemble.Inst
}

type functionScan struct {
	image      string
	classNames []string
	data       []byte
	start      uint64
	targets    map[uint64][]targetSpec
	mem        memoryReader
	secureOnly bool
}

func scanFunction(scan functionScan) []Record {
	instrs := decodeInstructions(scan.data, scan.start)
	var records []Record
	for idx, inst := range instrs {
		state := stateBeforeCall(instrs, idx, scan.targets, scan.mem)
		targets := callTargets(&inst.Inst, state, scan.targets)
		for _, target := range targets {
			records = append(records, recordsForTarget(scan, target, inst.Address, state)...)
		}
	}
	return records
}

func stateBeforeCall(instrs []decodedInst, callIndex int, targets map[uint64][]targetSpec, mem memoryReader) [31]regValue {
	var state [31]regValue
	for idx := range 8 {
		state[idx] = regValue{kind: valueParam, note: "param"}
	}
	start := max(callIndex-maxSliceInstructions, 0)
	for idx := start; idx < callIndex; idx++ {
		applyInstruction(&instrs[idx].Inst, state[:], targets, mem)
	}
	return state
}

func decodeInstructions(data []byte, start uint64) []decodedInst {
	var decoder disassemble.Decoder
	out := make([]decodedInst, 0, len(data)/4)
	r := bytes.NewReader(data)
	addr := start
	for {
		var raw uint32
		err := binary.Read(r, binary.LittleEndian, &raw)
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		var inst disassemble.Inst
		if err := decoder.DecomposeInto(addr, raw, &inst); err == nil {
			out = append(out, decodedInst{Inst: inst})
		}
		addr += 4
	}
	return out
}

func recordsForTarget(scan functionScan, target targetSpec, callsite uint64, state [31]regValue) []Record {
	if target.Kind != targetObjCMessage {
		return nil
	}
	selector, selectorNote := messageSelector(target, state, scan.mem)
	if selector == "" {
		return nil
	}
	switch selector {
	case selInterfaceWithProtocol:
		if scan.secureOnly {
			return nil
		}
		protocol, note := resolveProtocolRegister(state, 2, scan.mem)
		if protocol == "" {
			note = firstNote(note, selectorNote)
		}
		return []Record{{
			Kind:     KindInterface,
			Image:    scan.image,
			Callsite: fmt.Sprintf("%#x", callsite),
			Protocol: protocol,
			Resolved: protocol != "",
			Extra:    extraWithNote(note),
		}}
	case selSetClasses:
		if scan.secureOnly {
			return nil
		}
		classes, classNote := resolveClassSetRegister(state, 2, scan.mem)
		argSelector, argSelectorNote := resolveStringRegister(state, 3, scan.mem)
		argIndex, argNote := resolveIntRegister(state, 4)
		ofReply, replyNote := resolveBoolRegister(state, 5)
		protocol := ""
		var protocolNote string
		iface, ifaceNote := registerValue(state, 0)
		switch {
		case ifaceNote != "":
			protocolNote = ifaceNote
		case iface.kind == valueInterface && iface.protocol != "":
			protocol = iface.protocol
		default:
			protocolNote = noteFor(iface)
		}
		note := firstNote(protocolNote, classNote, argSelectorNote, argNote, replyNote)
		return []Record{{
			Kind:     KindInterfaceClasses,
			Image:    scan.image,
			Callsite: fmt.Sprintf("%#x", callsite),
			Protocol: protocol,
			Selector: argSelector,
			ArgIndex: argIndex,
			OfReply:  ofReply,
			Classes:  classes,
			Resolved: protocol != "" && protocolNote == "" && len(classes) > 0 && classNote == "" && argSelector != "" && argNote == "" && replyNote == "",
			Extra:    extraWithNote(note),
		}}
	case selDecodeObjectOfClass, selDecodeObjectOfClasses:
		if !scan.secureOnly {
			return nil
		}
		var classes []string
		var classNote string
		if selector == selDecodeObjectOfClass {
			if className, note := resolveClassRegister(state, 2, scan.mem); className != "" {
				classes = []string{className}
			} else {
				classNote = note
			}
		} else {
			classes, classNote = resolveClassSetRegister(state, 2, scan.mem)
		}
		key, _ := resolveStringRegister(state, 3, scan.mem)
		extra := extraWithNote(classNote)
		records := make([]Record, 0, len(scan.classNames))
		for _, className := range scan.classNames {
			records = append(records, Record{
				Kind:           KindSecureCodingDecode,
				Image:          scan.image,
				Class:          className,
				Callsite:       fmt.Sprintf("%#x", callsite),
				DecodedClasses: classes,
				Key:            key,
				Resolved:       len(classes) > 0 && classNote == "",
				Extra:          extra,
			})
		}
		return records
	default:
		return nil
	}
}

func extraWithNote(note string) map[string]string {
	if note == "" {
		return map[string]string{}
	}
	return map[string]string{"slice_notes": note}
}

func applyInstruction(inst *disassemble.Inst, state []regValue, targets map[uint64][]targetSpec, mem memoryReader) {
	switch inst.Operation {
	case disassemble.ARM64_ADR, disassemble.ARM64_ADRP:
		if rd, ok := destRegIndex(inst); ok {
			if imm, ok := operandImm(inst, 1); ok {
				state[rd] = regValue{kind: valueAddr, addr: imm}
			}
		}
	case disassemble.ARM64_ADD:
		applyAdd(inst, state)
	case disassemble.ARM64_LDR:
		applyLoad(inst, state, mem)
	case disassemble.ARM64_MOV:
		applyMove(inst, state)
	case disassemble.ARM64_MOVZ:
		if rd, ok := destRegIndex(inst); ok {
			if imm, ok := operandImm(inst, 1); ok {
				state[rd] = regValue{kind: valueImm, addr: imm}
			}
		}
	case disassemble.ARM64_MOVK:
		applyMoveKeep(inst, state)
	case disassemble.ARM64_ORR:
		if !applyORRMove(inst, state) {
			clearDest(inst, state, "indirect")
		}
	default:
		if isCall(inst.Operation) {
			applyCall(inst, state, targets, mem)
			return
		}
		if shouldClearDestination(inst) {
			clearDest(inst, state, "indirect")
		}
	}
	if isCall(inst.Operation) {
		applyCall(inst, state, targets, mem)
	}
}

func applyCall(inst *disassemble.Inst, state []regValue, targets map[uint64][]targetSpec, mem memoryReader) {
	var arr [31]regValue
	copy(arr[:], state)
	targetsForCall := callTargets(inst, arr, targets)
	ret := regValue{kind: valueUnknown, note: "indirect"}
	for _, target := range targetsForCall {
		if candidate, ok := returnValueForTarget(target, arr, mem); ok {
			ret = candidate
			break
		}
	}
	if len(targetsForCall) == 0 {
		if className, _ := resolveClassRegister(arr, 0, mem); className != "" {
			ret = regValue{kind: valueClass, text: className}
		}
	}
	clearVolatile(state)
	state[0] = ret
}

func returnValueForTarget(target targetSpec, state [31]regValue, mem memoryReader) (regValue, bool) {
	switch target.Kind {
	case targetObjCGetClass:
		if target.Name == "objc_opt_class" {
			className, note := resolveClassRegister(state, 0, mem)
			if className != "" {
				return regValue{kind: valueClass, text: className}, true
			}
			return regValue{kind: valueUnknown, note: firstNote(note, "indirect")}, true
		}
		name, note := resolveStringRegister(state, 0, mem)
		if name == "" {
			return regValue{kind: valueUnknown, note: firstNote(note, "indirect")}, true
		}
		return regValue{kind: valueClass, text: name}, true
	case targetObjCGetProtocol:
		name, note := resolveStringRegister(state, 0, mem)
		if name == "" {
			return regValue{kind: valueUnknown, note: firstNote(note, "indirect")}, true
		}
		return regValue{kind: valueProtocol, text: name}, true
	case targetObjCMessage:
		selector, _ := messageSelector(target, state, mem)
		switch selector {
		case selInterfaceWithProtocol:
			protocol, note := resolveProtocolRegister(state, 2, mem)
			if protocol == "" {
				return regValue{kind: valueUnknown, note: firstNote(note, "indirect")}, true
			}
			return regValue{kind: valueInterface, protocol: protocol}, true
		case selSetWithObject:
			className, note := resolveClassRegister(state, 2, mem)
			if className == "" {
				return regValue{kind: valueUnknown, note: firstNote(note, "indirect")}, true
			}
			return regValue{kind: valueClasses, items: []string{className}}, true
		case selSetWithObjects, selArrayWithObjects:
			classes := make([]string, 0, 6)
			terminated := false
			var setNote string
			for reg := 2; reg <= 7; reg++ {
				val, note := registerValue(state, reg)
				if note == "" && val.kind == valueImm && val.addr == 0 {
					terminated = true
					break
				}
				className, classNote := resolveClassValue(val, mem)
				if className != "" {
					classes = append(classes, className)
					continue
				}
				setNote = firstNote(note, classNote, "indirect")
				break
			}
			if len(classes) == 0 {
				return regValue{kind: valueUnknown, note: firstNote(setNote, "indirect")}, true
			}
			if !terminated {
				setNote = firstNote(setNote, "truncated")
			}
			return regValue{kind: valueClasses, items: sortedStrings(classes), note: setNote}, true
		}
	}
	return regValue{}, false
}

func callTargets(inst *disassemble.Inst, state [31]regValue, targets map[uint64][]targetSpec) []targetSpec {
	switch inst.Operation {
	case disassemble.ARM64_BL, disassemble.ARM64_B:
		if target, ok := labelTarget(inst); ok {
			return targets[target]
		}
	case disassemble.ARM64_BLR, disassemble.ARM64_BLRAA, disassemble.ARM64_BLRAAZ,
		disassemble.ARM64_BLRAB, disassemble.ARM64_BLRABZ,
		disassemble.ARM64_BR, disassemble.ARM64_BRAA, disassemble.ARM64_BRAAZ:
		if reg, ok := operandReg(inst, 0); ok {
			if idx, ok := regIndex(reg); ok {
				val := state[idx]
				if (val.kind == valueAddr || val.kind == valueImm) && val.addr != 0 {
					return targets[val.addr]
				}
			}
		}
	}
	return nil
}

func applyAdd(inst *disassemble.Inst, state []regValue) {
	rd, ok := destRegIndex(inst)
	if !ok {
		return
	}
	rn, ok := operandRegIndex(inst, 1)
	if !ok {
		state[rd] = regValue{kind: valueUnknown, note: "indirect"}
		return
	}
	imm, ok := operandImm(inst, 2)
	if !ok {
		state[rd] = regValue{kind: valueUnknown, note: "indirect"}
		return
	}
	base := state[rn]
	if base.kind == valueAddr || base.kind == valueImm {
		state[rd] = regValue{kind: base.kind, addr: base.addr + imm}
		return
	}
	state[rd] = regValue{kind: valueUnknown, note: noteFor(base)}
}

func applyLoad(inst *disassemble.Inst, state []regValue, mem memoryReader) {
	rd, ok := destRegIndex(inst)
	if !ok {
		return
	}
	if target, ok := labelTarget(inst); ok {
		if className, ok := mem.ClassName(target); ok {
			state[rd] = regValue{kind: valueClass, text: className}
			return
		}
		if protocolName, ok := mem.ProtocolName(target); ok {
			state[rd] = regValue{kind: valueProtocol, text: protocolName}
			return
		}
		if ptr, err := mem.ReadPointer(target); err == nil && ptr != 0 {
			state[rd] = regValue{kind: valueAddr, addr: ptr}
		} else {
			state[rd] = regValue{kind: valueUnknown, note: "indirect"}
		}
		return
	}
	baseReg, ok := operandRegIndex(inst, 1)
	if !ok {
		state[rd] = regValue{kind: valueUnknown, note: "indirect"}
		return
	}
	base := state[baseReg]
	if base.kind != valueAddr && base.kind != valueImm {
		state[rd] = regValue{kind: valueUnknown, note: noteFor(base)}
		return
	}
	off, ok := operandImm(inst, 1)
	if !ok {
		state[rd] = regValue{kind: valueUnknown, note: "indirect"}
		return
	}
	loc := base.addr + off
	if className, ok := mem.ClassName(loc); ok {
		state[rd] = regValue{kind: valueClass, text: className}
		return
	}
	if protocolName, ok := mem.ProtocolName(loc); ok {
		state[rd] = regValue{kind: valueProtocol, text: protocolName}
		return
	}
	ptr, err := mem.ReadPointer(loc)
	if err != nil || ptr == 0 {
		state[rd] = regValue{kind: valueUnknown, note: "indirect"}
		return
	}
	state[rd] = regValue{kind: valueAddr, addr: ptr}
}

func applyMove(inst *disassemble.Inst, state []regValue) {
	rd, ok := destRegIndex(inst)
	if !ok {
		return
	}
	if reg, ok := operandReg(inst, 1); ok {
		if isZeroReg(reg) {
			state[rd] = regValue{kind: valueImm, addr: 0}
			return
		}
		if rn, ok := regIndex(reg); ok {
			state[rd] = state[rn]
			return
		}
		state[rd] = regValue{kind: valueUnknown, note: "indirect"}
		return
	}
	if imm, ok := operandImm(inst, 1); ok {
		state[rd] = regValue{kind: valueImm, addr: imm}
		return
	}
	state[rd] = regValue{kind: valueUnknown, note: "indirect"}
}

func applyMoveKeep(inst *disassemble.Inst, state []regValue) {
	rd, ok := destRegIndex(inst)
	if !ok {
		return
	}
	imm, ok := operandImm(inst, 1)
	if !ok {
		state[rd] = regValue{kind: valueUnknown, note: "indirect"}
		return
	}
	prev := state[rd]
	if prev.kind != valueImm && prev.kind != valueAddr {
		state[rd] = regValue{kind: valueUnknown, note: noteFor(prev)}
		return
	}
	shift := uint64(0)
	if inst.NumOps > 1 && inst.Operands[1].ShiftValueUsed {
		shift = uint64(inst.Operands[1].ShiftValue)
	}
	mask := uint64(0xffff) << shift
	state[rd] = regValue{kind: prev.kind, addr: (prev.addr &^ mask) | (imm & mask)}
}

func applyORRMove(inst *disassemble.Inst, state []regValue) bool {
	rd, ok := destRegIndex(inst)
	if !ok {
		return false
	}
	rn, rnOK := operandReg(inst, 1)
	rm, rmOK := operandReg(inst, 2)
	if rnOK && rmOK && isZeroReg(rn) {
		if idx, ok := regIndex(rm); ok {
			state[rd] = state[idx]
			return true
		}
	}
	return false
}

func messageSelector(target targetSpec, state [31]regValue, mem memoryReader) (string, string) {
	if target.Selector != "" {
		return target.Selector, ""
	}
	return resolveStringRegister(state, 1, mem)
}

func resolveStringRegister(state [31]regValue, reg int, mem memoryReader) (string, string) {
	val, note := registerValue(state, reg)
	if note != "" {
		return "", note
	}
	return resolveStringValue(val, mem)
}

func resolveStringValue(val regValue, mem memoryReader) (string, string) {
	if val.kind == valueString {
		return val.text, ""
	}
	if val.kind == valueAddr || val.kind == valueImm {
		if str, ok := resolveString(val.addr, mem); ok {
			return str, ""
		}
		return "", "indirect"
	}
	return "", noteFor(val)
}

func resolveProtocolRegister(state [31]regValue, reg int, mem memoryReader) (string, string) {
	val, note := registerValue(state, reg)
	if note != "" {
		return "", note
	}
	if val.kind == valueProtocol {
		return val.text, ""
	}
	if val.kind == valueAddr || val.kind == valueImm {
		if name, ok := mem.ProtocolName(val.addr); ok {
			return name, ""
		}
		if ptr, err := mem.ReadPointer(val.addr); err == nil && ptr != 0 {
			if name, ok := mem.ProtocolName(ptr); ok {
				return name, ""
			}
		}
	}
	return "", "indirect"
}

func resolveClassRegister(state [31]regValue, reg int, mem memoryReader) (string, string) {
	val, note := registerValue(state, reg)
	if note != "" {
		return "", note
	}
	return resolveClassValue(val, mem)
}

func resolveClassValue(val regValue, mem memoryReader) (string, string) {
	switch val.kind {
	case valueClass:
		return val.text, ""
	case valueClasses:
		if len(val.items) == 1 {
			return val.items[0], ""
		}
		return "", "indirect"
	case valueAddr, valueImm:
		if name, ok := mem.ClassPointerName(val.addr); ok {
			return name, ""
		}
		if ptr, err := mem.ReadPointer(val.addr); err == nil && ptr != 0 {
			if name, ok := mem.ClassPointerName(ptr); ok {
				return name, ""
			}
		}
		return "", "indirect"
	default:
		return "", noteFor(val)
	}
}

func resolveClassSetRegister(state [31]regValue, reg int, mem memoryReader) ([]string, string) {
	val, note := registerValue(state, reg)
	if note != "" {
		return nil, note
	}
	switch val.kind {
	case valueClasses:
		return sortedStrings(val.items), val.note
	case valueClass:
		return []string{val.text}, ""
	case valueAddr, valueImm:
		if className, _ := resolveClassValue(val, mem); className != "" {
			return []string{className}, ""
		}
		if classes, ok := resolveClassPointerArray(val.addr, mem); ok {
			return classes, ""
		}
		return nil, "indirect"
	default:
		return nil, noteFor(val)
	}
}

func resolveClassPointerArray(addr uint64, mem memoryReader) ([]string, bool) {
	for _, layout := range []struct {
		countOffset  uint64
		valuesOffset uint64
	}{
		{countOffset: 16, valuesOffset: 24},
		{countOffset: 24, valuesOffset: 16},
	} {
		count, err := mem.ReadUint64(addr + layout.countOffset)
		if err != nil || count == 0 || count > 128 {
			continue
		}
		values, err := mem.ReadPointer(addr + layout.valuesOffset)
		if err != nil || values == 0 {
			continue
		}
		classes := make([]string, 0, count)
		for idx := range count {
			ptr, err := mem.ReadPointer(values + idx*8)
			if err != nil || ptr == 0 {
				classes = classes[:0]
				break
			}
			name, note := resolveClassValue(regValue{kind: valueAddr, addr: ptr}, mem)
			if note != "" || name == "" {
				classes = classes[:0]
				break
			}
			classes = append(classes, name)
		}
		if len(classes) == int(count) {
			return sortedStrings(classes), true
		}
	}
	return nil, false
}

func resolveIntRegister(state [31]regValue, reg int) (int, string) {
	val, note := registerValue(state, reg)
	if note != "" {
		return 0, note
	}
	if val.kind == valueImm || val.kind == valueAddr {
		return int(val.addr), ""
	}
	return 0, noteFor(val)
}

func resolveBoolRegister(state [31]regValue, reg int) (bool, string) {
	val, note := registerValue(state, reg)
	if note != "" {
		return false, note
	}
	if val.kind == valueImm || val.kind == valueAddr {
		return val.addr != 0, ""
	}
	return false, noteFor(val)
}

func registerValue(state [31]regValue, reg int) (regValue, string) {
	if reg < 0 || reg >= len(state) {
		return regValue{}, "indirect"
	}
	val := state[reg]
	if val.kind == valueParam {
		return val, "param"
	}
	if val.kind == valueUnknown {
		return val, noteFor(val)
	}
	return val, ""
}

func resolveString(addr uint64, mem memoryReader) (string, bool) {
	if s, ok := readCString(mem, addr); ok {
		return s, true
	}
	if s, ok := readCFString(mem, addr); ok {
		return s, true
	}
	if ptr, err := mem.ReadPointer(addr); err == nil && ptr != 0 {
		if s, ok := readCString(mem, ptr); ok {
			return s, true
		}
		if s, ok := readCFString(mem, ptr); ok {
			return s, true
		}
	}
	return "", false
}

func readCFString(mem memoryReader, addr uint64) (string, bool) {
	ptr, err := mem.ReadPointer(addr + 16)
	if err != nil || ptr == 0 {
		return "", false
	}
	return readCString(mem, ptr)
}

func readCString(mem memoryReader, addr uint64) (string, bool) {
	s, err := mem.ReadCString(addr)
	if err != nil || !validLiteralString(s) {
		return "", false
	}
	return s, true
}

func validLiteralString(s string) bool {
	if s == "" || len(s) > 4096 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func labelTarget(inst *disassemble.Inst) (uint64, bool) {
	for idx := 0; idx < int(inst.NumOps); idx++ {
		op := &inst.Operands[idx]
		if op.Class == disassemble.LABEL {
			return op.GetImmediate(), true
		}
	}
	return 0, false
}

func operandReg(inst *disassemble.Inst, idx int) (disassemble.Register, bool) {
	if inst == nil || int(inst.NumOps) <= idx || inst.Operands[idx].NumRegisters == 0 {
		return disassemble.REG_NONE, false
	}
	return inst.Operands[idx].Registers[0], true
}

func operandRegIndex(inst *disassemble.Inst, idx int) (int, bool) {
	reg, ok := operandReg(inst, idx)
	if !ok {
		return 0, false
	}
	return regIndex(reg)
}

func operandImm(inst *disassemble.Inst, idx int) (uint64, bool) {
	if inst == nil || int(inst.NumOps) <= idx {
		return 0, false
	}
	op := &inst.Operands[idx]
	switch op.Class {
	case disassemble.IMM32, disassemble.IMM64, disassemble.STR_IMM,
		disassemble.MEM_PRE_IDX, disassemble.MEM_POST_IDX, disassemble.MEM_OFFSET,
		disassemble.LABEL:
		return op.GetImmediate(), true
	default:
		return 0, false
	}
}

func destRegIndex(inst *disassemble.Inst) (int, bool) {
	return operandRegIndex(inst, 0)
}

func regIndex(reg disassemble.Register) (int, bool) {
	switch {
	case reg >= disassemble.REG_X0 && reg <= disassemble.REG_X30:
		return int(reg - disassemble.REG_X0), true
	case reg >= disassemble.REG_W0 && reg <= disassemble.REG_W30:
		return int(reg - disassemble.REG_W0), true
	default:
		return 0, false
	}
}

func isZeroReg(reg disassemble.Register) bool {
	return reg == disassemble.REG_XZR || reg == disassemble.REG_WZR
}

func clearDest(inst *disassemble.Inst, state []regValue, note string) {
	if rd, ok := destRegIndex(inst); ok {
		state[rd] = regValue{kind: valueUnknown, note: note}
	}
}

func clearVolatile(state []regValue) {
	for idx := 0; idx <= 17 && idx < len(state); idx++ {
		state[idx] = regValue{kind: valueUnknown, note: "indirect"}
	}
}

func isCall(op disassemble.Operation) bool {
	switch op {
	case disassemble.ARM64_BL, disassemble.ARM64_BLR,
		disassemble.ARM64_BLRAA, disassemble.ARM64_BLRAAZ,
		disassemble.ARM64_BLRAB, disassemble.ARM64_BLRABZ:
		return true
	default:
		return false
	}
}

func shouldClearDestination(inst *disassemble.Inst) bool {
	if inst == nil || inst.NumOps == 0 {
		return false
	}
	if _, ok := destRegIndex(inst); !ok {
		return false
	}
	op := strings.ToLower(inst.Operation.String())
	if strings.HasPrefix(op, "st") || strings.HasPrefix(op, "b.") || op == "b" || op == "br" || op == "ret" {
		return false
	}
	if disass.IsBranchOp(inst.Operation) {
		return false
	}
	return true
}

func noteFor(val regValue) string {
	if val.note != "" {
		return val.note
	}
	if val.kind == valueParam {
		return "param"
	}
	return "indirect"
}

func firstNote(notes ...string) string {
	for _, note := range notes {
		if note != "" {
			return note
		}
	}
	return ""
}
