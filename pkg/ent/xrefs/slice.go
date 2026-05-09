package xrefs

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
}

type valueKind uint8

const (
	valueUnknown valueKind = iota
	valueParam
	valueAddr
	valueImm
)

type regValue struct {
	kind valueKind
	addr uint64
	note string
}

type resolvedArg struct {
	value string
	note  string
}

type decodedInst struct {
	disassemble.Inst
}

type functionScan struct {
	source       Source
	image        string
	callerSymbol string
	data         []byte
	start        uint64
	targets      map[uint64][]targetSpec
	mem          memoryReader
}

func scanFunction(scan functionScan) []Record {
	instrs := decodeInstructions(scan.data, scan.start)
	var records []Record
	for idx, inst := range instrs {
		state := stateBeforeCall(instrs, idx, scan.mem)
		if targets := scan.callTargets(&inst.Inst, state); len(targets) > 0 {
			for _, target := range targets {
				if target.Selector != "" {
					selector, _ := resolveRegister(state, target.SelectorReg, scan.mem)
					if selector != target.Selector {
						continue
					}
				}
				value := ""
				if target.hasValue() {
					if v, _ := resolveRegister(state, target.ValueReg, scan.mem); v != "" {
						value = v
					}
				}
				for _, key := range resolveTargetKeys(state, target, scan.mem) {
					rec := Record{
						Source:       string(scan.source),
						Image:        scan.image,
						CallerSymbol: scan.callerSymbol,
						Callsite:     fmt.Sprintf("%#x", inst.Address),
						CheckFn:      target.Canonical,
						Key:          key.value,
						Value:        value,
						Resolved:     key.value != "",
						Extra:        map[string]string{},
					}
					if key.value == "" {
						note := key.note
						if note == "" {
							note = "indirect"
						}
						rec.Extra["slice_notes"] = note
					}
					records = append(records, rec)
				}
			}
		}
	}
	return records
}

func stateBeforeCall(instrs []decodedInst, callIndex int, mem memoryReader) [31]regValue {
	var state [31]regValue
	for idx := range 8 {
		state[idx] = regValue{kind: valueParam, note: "param"}
	}
	start := max(callIndex-maxSliceInstructions, 0)
	for idx := start; idx < callIndex; idx++ {
		applyInstruction(&instrs[idx].Inst, state[:], mem)
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

func (scan functionScan) callTargets(inst *disassemble.Inst, state [31]regValue) []targetSpec {
	switch inst.Operation {
	case disassemble.ARM64_BL, disassemble.ARM64_B:
		if target, ok := labelTarget(inst); ok {
			return scan.targets[target]
		}
	case disassemble.ARM64_BLR, disassemble.ARM64_BLRAA, disassemble.ARM64_BLRAAZ,
		disassemble.ARM64_BLRAB, disassemble.ARM64_BLRABZ,
		disassemble.ARM64_BR, disassemble.ARM64_BRAA, disassemble.ARM64_BRAAZ:
		if reg, ok := operandReg(inst, 0); ok {
			if idx, ok := regIndex(reg); ok {
				val := state[idx]
				if (val.kind == valueAddr || val.kind == valueImm) && val.addr != 0 {
					return scan.targets[val.addr]
				}
			}
		}
	}
	return nil
}

func applyInstruction(inst *disassemble.Inst, state []regValue, mem memoryReader) {
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
			clearVolatile(state)
			return
		}
		if shouldClearDestination(inst) {
			clearDest(inst, state, "indirect")
		}
	}
	if isCall(inst.Operation) {
		clearVolatile(state)
	}
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
	off, _ := operandImm(inst, 1)
	ptr, err := mem.ReadPointer(base.addr + off)
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
	if rn, ok := operandRegIndex(inst, 1); ok {
		state[rd] = state[rn]
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

func resolveRegister(state [31]regValue, reg int, mem memoryReader) (string, string) {
	val, note := registerValue(state, reg)
	if note != "" {
		return "", note
	}
	if str, ok := resolveString(val.addr, mem); ok {
		return str, ""
	}
	return "", "indirect"
}

func resolveTargetKeys(state [31]regValue, target targetSpec, mem memoryReader) []resolvedArg {
	val, note := registerValue(state, target.KeyReg)
	if note != "" {
		return []resolvedArg{{note: note}}
	}
	if target.KeyArray {
		if keys, ok := resolveStringArray(val.addr, mem); ok {
			out := make([]resolvedArg, 0, len(keys))
			for _, key := range keys {
				out = append(out, resolvedArg{value: key})
			}
			return out
		}
		return []resolvedArg{{note: "indirect"}}
	}
	if str, ok := resolveString(val.addr, mem); ok {
		return []resolvedArg{{value: str}}
	}
	return []resolvedArg{{note: "indirect"}}
}

func registerValue(state [31]regValue, reg int) (regValue, string) {
	if reg < 0 || reg >= len(state) {
		return regValue{}, "indirect"
	}
	val := state[reg]
	if val.kind == valueParam {
		return val, "param"
	}
	if val.kind != valueAddr && val.kind != valueImm {
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

func resolveStringArray(addr uint64, mem memoryReader) ([]string, bool) {
	for _, layout := range []struct {
		countOffset  uint64
		valuesOffset uint64
	}{
		{countOffset: 16, valuesOffset: 24},
		{countOffset: 24, valuesOffset: 16},
	} {
		count, err := mem.ReadUint64(addr + layout.countOffset)
		if err != nil || count == 0 || count > 64 {
			continue
		}
		values, err := mem.ReadPointer(addr + layout.valuesOffset)
		if err != nil || values == 0 {
			continue
		}
		strings := make([]string, 0, count)
		for idx := range count {
			ptr, err := mem.ReadPointer(values + idx*8)
			if err != nil || ptr == 0 {
				strings = strings[:0]
				break
			}
			str, ok := resolveString(ptr, mem)
			if !ok {
				strings = strings[:0]
				break
			}
			strings = append(strings, str)
		}
		if len(strings) == int(count) {
			return strings, true
		}
	}
	return nil, false
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
