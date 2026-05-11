package xrefs

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/ipsw/pkg/xref"
)

type memoryReader interface {
	xref.MemoryReader
	ReadUint64(addr uint64) (uint64, error)
	ReadCString(addr uint64) (string, error)
}

type resolvedArg struct {
	value string
	note  string
}

type functionScan struct {
	source       Source
	image        string
	callerSymbol string
	data         []byte
	start        uint64
	targets      map[uint64][]targetSpec
	targetAddrs  xref.TargetSet
	virtualSlots map[int][]targetSpec
	mem          memoryReader
	skipIndirect bool
	allowVirtual bool
	scanner      *xref.Scanner
	targetHints  targetHints
}

type targetHints struct {
	set            bool
	hasKeyArray    bool
	hasVirtualSlot bool
}

func scanFunction(scan functionScan) []Record {
	instrs := []xref.Instruction(nil)
	var special specialScanResult
	needsArrayScan := scan.targetHints.hasKeyArray
	needsVirtualSlotScan := scan.targetHints.hasVirtualSlot
	if !scan.targetHints.set {
		needsArrayScan = hasKeyArrayTargets(scan.targets)
		needsVirtualSlotScan = len(scan.virtualSlots) > 0
	}
	needsVirtualSlotScan = needsVirtualSlotScan && scan.allowVirtual
	if needsArrayScan || needsVirtualSlotScan {
		if scan.scanner != nil {
			instrs = scan.scanner.Decode(scan.data, scan.start)
		} else {
			instrs = xref.Decode(scan.data, scan.start)
		}
	}

	targetAddrs := scan.targetAddrs
	if targetAddrs == nil {
		targetAddrs = targetSetFromSpecs(scan.targets)
	}
	opts := xref.Options{
		Targets:         targetAddrs,
		Reader:          scan.mem,
		Mode:            xref.ModeCalls,
		ResolveIndirect: !scan.skipIndirect,
	}
	var results []xref.Result
	if len(instrs) > 0 {
		results = xref.ScanInstructions(instrs, opts)
	} else if scan.scanner != nil {
		results = scan.scanner.ScanFunction(scan.data, scan.start, opts)
	} else {
		results = xref.ScanFunction(scan.data, scan.start, opts)
	}
	if needsArrayScan && resultsContainKeyArrayTarget(scan.targets, results) {
		arrayResult := scanStackCFArrayCalls(scan, instrs)
		special.records = append(special.records, arrayResult.records...)
		for addr := range arrayResult.handled {
			special.markHandled(addr)
		}
	}
	if needsVirtualSlotScan {
		special.records = append(special.records, scanVirtualSlotCalls(scan, instrs)...)
	}
	records := special.records
	for _, result := range results {
		for _, target := range scan.targets[result.Target] {
			if target.KeyArray {
				if _, ok := special.handled[result.Address]; ok {
					continue
				}
			}
			if target.Selector != "" {
				selector, _ := resolveRegister(result.State, target.SelectorReg, scan.mem)
				if selector != target.Selector {
					continue
				}
			}
			value := ""
			if target.hasValue() {
				if v, _ := resolveRegister(result.State, target.ValueReg, scan.mem); v != "" {
					value = v
				}
			}
			for _, key := range resolveTargetKeys(result.State, target, scan.mem) {
				records = append(records, buildRecord(scan, result.Address, target, key, value))
			}
		}
	}
	return records
}

type specialScanResult struct {
	records []Record
	handled map[uint64]struct{}
}

func (r *specialScanResult) markHandled(addr uint64) {
	if r.handled == nil {
		r.handled = make(map[uint64]struct{})
	}
	r.handled[addr] = struct{}{}
}

func hasKeyArrayTargets(targets map[uint64][]targetSpec) bool {
	for _, specs := range targets {
		for _, spec := range specs {
			if spec.KeyArray {
				return true
			}
		}
	}
	return false
}

func hintsForTargets(targets map[uint64][]targetSpec, virtualSlots map[int][]targetSpec) targetHints {
	return targetHints{
		set:            true,
		hasKeyArray:    hasKeyArrayTargets(targets),
		hasVirtualSlot: len(virtualSlots) > 0,
	}
}

func resultsContainKeyArrayTarget(targets map[uint64][]targetSpec, results []xref.Result) bool {
	for _, result := range results {
		for _, target := range targets[result.Target] {
			if target.KeyArray {
				return true
			}
		}
	}
	return false
}

func buildRecord(scan functionScan, callsite uint64, target targetSpec, key resolvedArg, value string) Record {
	rec := Record{
		Source:       string(scan.source),
		Image:        scan.image,
		CallerSymbol: scan.callerSymbol,
		Callsite:     fmt.Sprintf("%#x", callsite),
		CheckFn:      target.Canonical,
		Key:          key.value,
		Value:        value,
		Resolved:     key.value != "",
		Extra:        map[string]string{},
	}
	if target.Discovery != "" {
		rec.Extra["target_discovery"] = target.Discovery
	}
	if key.value == "" {
		note := key.note
		if note == "" {
			note = "indirect"
		}
		rec.Extra["slice_notes"] = note
	}
	return rec
}

const (
	syntheticStackBase uint64 = 0xf100000000000000
	syntheticArrayBase uint64 = 0xf200000000000000
)

type cfArrayTracker struct {
	scan             functionScan
	regs             xref.RegisterState
	stack            map[uint64]uint64
	arrays           map[uint64][]string
	nextArray        uint64
	freshArrayReturn bool
}

func scanStackCFArrayCalls(scan functionScan, instrs []xref.Instruction) specialScanResult {
	var out specialScanResult
	if scan.targetHints.set && !scan.targetHints.hasKeyArray {
		return out
	}
	if !scan.targetHints.set && !hasKeyArrayTargets(scan.targets) {
		return out
	}
	tracker := cfArrayTracker{
		scan:      scan,
		stack:     make(map[uint64]uint64),
		arrays:    make(map[uint64][]string),
		nextArray: syntheticArrayBase,
	}
	for idx := range 8 {
		tracker.regs[idx] = xref.RegisterValue{Kind: xref.ValueParam, Note: "param"}
	}
	for idx := range instrs {
		inst := &instrs[idx].Inst
		if target, ok := directCallTarget(inst); ok {
			if tracker.recordKeyArrayCall(&out, inst.Address, target) {
				tracker.applyCall(nil)
				continue
			}
			if arrayID, ok := tracker.arrayFromCallArgs(); ok {
				tracker.applyCall(&arrayID)
				continue
			}
			tracker.applyCall(nil)
			continue
		}
		if isCallOp(inst.Operation) {
			tracker.applyCall(nil)
			continue
		}
		tracker.apply(inst)
	}
	return out
}

func (t *cfArrayTracker) recordKeyArrayCall(out *specialScanResult, callsite uint64, targetAddr uint64) bool {
	handled := false
	for _, target := range t.scan.targets[targetAddr] {
		if !target.KeyArray {
			continue
		}
		keys, ok := t.keysForReg(target.KeyReg)
		if !ok {
			continue
		}
		for _, key := range keys {
			out.records = append(out.records, buildRecord(t.scan, callsite, target, resolvedArg{value: key}, ""))
		}
		out.markHandled(callsite)
		handled = true
	}
	return handled
}

func (t *cfArrayTracker) keysForReg(reg int) ([]string, bool) {
	if reg < 0 || reg >= len(t.regs) {
		return nil, false
	}
	val := t.regs[reg]
	if keys, ok := t.arrays[val.Addr]; ok {
		return keys, true
	}
	if !val.KnownAddress() {
		return nil, false
	}
	return resolveStringArray(val.Addr, t.scan.mem)
}

func (t *cfArrayTracker) arrayFromCallArgs() (uint64, bool) {
	for _, args := range []struct {
		baseReg  int
		countReg int
	}{
		{baseReg: 2, countReg: 3},
		{baseReg: 0, countReg: 1},
	} {
		base := t.regs[args.baseReg]
		count := t.regs[args.countReg]
		if !base.KnownAddress() || !count.KnownAddress() || count.Addr == 0 || count.Addr > 64 {
			continue
		}
		if base.Addr < syntheticStackBase || base.Addr >= syntheticStackBase+0x1000000 {
			continue
		}
		keys := make([]string, 0, count.Addr)
		for idx := uint64(0); idx < count.Addr; idx++ {
			ptr := t.stack[base.Addr+idx*8]
			if ptr == 0 {
				keys = keys[:0]
				break
			}
			key, ok := resolveString(ptr, t.scan.mem)
			if !ok {
				keys = keys[:0]
				break
			}
			keys = append(keys, key)
		}
		if len(keys) == int(count.Addr) {
			arrayID := t.nextArray
			t.nextArray += 8
			t.arrays[arrayID] = keys
			return arrayID, true
		}
	}
	return 0, false
}

func (t *cfArrayTracker) applyCall(arrayID *uint64) {
	preserveArray := uint64(0)
	if t.freshArrayReturn {
		val := t.regs[0]
		if _, ok := t.arrays[val.Addr]; ok {
			preserveArray = val.Addr
		}
	}
	for idx := 0; idx <= 17 && idx < len(t.regs); idx++ {
		t.regs[idx] = xref.RegisterValue{Kind: xref.ValueUnknown, Note: "indirect"}
	}
	t.freshArrayReturn = false
	if arrayID != nil {
		t.regs[0] = xref.RegisterValue{Kind: xref.ValueAddr, Addr: *arrayID}
		t.freshArrayReturn = true
		return
	}
	if preserveArray != 0 {
		t.regs[0] = xref.RegisterValue{Kind: xref.ValueAddr, Addr: preserveArray}
	}
}

func (t *cfArrayTracker) apply(inst *disassemble.Inst) {
	switch inst.Operation {
	case disassemble.ARM64_ADR, disassemble.ARM64_ADRP:
		if rd, ok := destRegIndex(inst); ok {
			if imm, ok := xref.OperandImm(inst, 1); ok {
				t.regs[rd] = xref.RegisterValue{Kind: xref.ValueAddr, Addr: imm}
			}
		}
	case disassemble.ARM64_ADD:
		t.applyAdd(inst)
	case disassemble.ARM64_LDR, disassemble.ARM64_LDUR:
		t.applyLoad(inst)
	case disassemble.ARM64_STP:
		t.applyStorePair(inst)
	case disassemble.ARM64_STR, disassemble.ARM64_STUR:
		t.applyStore(inst)
	case disassemble.ARM64_MOV:
		t.applyMove(inst)
	case disassemble.ARM64_MOVZ:
		if rd, ok := destRegIndex(inst); ok {
			if imm, ok := xref.OperandImm(inst, 1); ok {
				t.regs[rd] = xref.RegisterValue{Kind: xref.ValueImm, Addr: imm}
			}
		}
	case disassemble.ARM64_MOVK:
		t.applyMoveKeep(inst)
	case disassemble.ARM64_ORR:
		if !t.applyORRMove(inst) {
			t.clearDest(inst, "indirect")
		}
	default:
		if shouldClearDestinationLocal(inst) {
			t.clearDest(inst, "indirect")
		}
	}
}

func (t *cfArrayTracker) applyAdd(inst *disassemble.Inst) {
	rd, ok := destRegIndex(inst)
	if !ok {
		return
	}
	imm, ok := xref.OperandImm(inst, 2)
	if !ok {
		t.regs[rd] = xref.RegisterValue{Kind: xref.ValueUnknown, Note: "indirect"}
		return
	}
	rn, ok := xref.OperandReg(inst, 1)
	if !ok {
		t.regs[rd] = xref.RegisterValue{Kind: xref.ValueUnknown, Note: "indirect"}
		return
	}
	if isSP(rn) {
		t.regs[rd] = xref.RegisterValue{Kind: xref.ValueAddr, Addr: syntheticStackBase + imm}
		return
	}
	rnIdx, ok := xref.RegIndex(rn)
	if !ok {
		t.regs[rd] = xref.RegisterValue{Kind: xref.ValueUnknown, Note: "indirect"}
		return
	}
	base := t.regs[rnIdx]
	if base.KnownAddress() {
		t.regs[rd] = xref.RegisterValue{Kind: base.Kind, Addr: base.Addr + imm}
		return
	}
	t.regs[rd] = xref.RegisterValue{Kind: xref.ValueUnknown, Note: base.UnresolvedNote()}
}

func (t *cfArrayTracker) applyLoad(inst *disassemble.Inst) {
	rd, ok := destRegIndex(inst)
	if !ok {
		return
	}
	if target, ok := xref.LabelTarget(inst); ok {
		t.regs[rd] = t.readPointerValue(target)
		return
	}
	addr, ok := t.memoryAddress(inst, 1)
	if !ok {
		t.regs[rd] = xref.RegisterValue{Kind: xref.ValueUnknown, Note: "indirect"}
		return
	}
	if ptr := t.stack[addr]; ptr != 0 {
		t.regs[rd] = xref.RegisterValue{Kind: xref.ValueAddr, Addr: ptr}
		return
	}
	t.regs[rd] = t.readPointerValue(addr)
}

func (t *cfArrayTracker) readPointerValue(addr uint64) xref.RegisterValue {
	if t.scan.mem == nil {
		return xref.RegisterValue{Kind: xref.ValueUnknown, Note: "indirect"}
	}
	ptr, err := t.scan.mem.ReadPointer(addr)
	if err != nil || ptr == 0 {
		return xref.RegisterValue{Kind: xref.ValueUnknown, Note: "indirect"}
	}
	return xref.RegisterValue{Kind: xref.ValueAddr, Addr: ptr}
}

func (t *cfArrayTracker) applyStore(inst *disassemble.Inst) {
	src, ok := xref.OperandRegIndex(inst, 0)
	if !ok {
		return
	}
	addr, ok := t.memoryAddress(inst, 1)
	if !ok {
		return
	}
	val := t.regs[src]
	if val.KnownAddress() && val.Addr != 0 {
		t.stack[addr] = val.Addr
	}
}

func (t *cfArrayTracker) applyStorePair(inst *disassemble.Inst) {
	first, firstOK := xref.OperandRegIndex(inst, 0)
	second, secondOK := xref.OperandRegIndex(inst, 1)
	addr, addrOK := t.memoryAddress(inst, 2)
	if !addrOK {
		return
	}
	if firstOK {
		if val := t.regs[first]; val.KnownAddress() && val.Addr != 0 {
			t.stack[addr] = val.Addr
		}
	}
	if secondOK {
		if val := t.regs[second]; val.KnownAddress() && val.Addr != 0 {
			t.stack[addr+8] = val.Addr
		}
	}
}

func (t *cfArrayTracker) memoryAddress(inst *disassemble.Inst, operand int) (uint64, bool) {
	baseReg, ok := xref.OperandReg(inst, operand)
	if !ok {
		return 0, false
	}
	offset, _, _, ok := xref.MemoryAccess(inst, operand)
	if !ok {
		return 0, false
	}
	if isSP(baseReg) {
		return syntheticStackBase + offset, true
	}
	baseIdx, ok := xref.RegIndex(baseReg)
	if !ok {
		return 0, false
	}
	base := t.regs[baseIdx]
	if !base.KnownAddress() {
		return 0, false
	}
	return base.Addr + offset, true
}

func (t *cfArrayTracker) applyMove(inst *disassemble.Inst) {
	rd, ok := destRegIndex(inst)
	if !ok {
		return
	}
	if rn, ok := xref.OperandRegIndex(inst, 1); ok {
		t.regs[rd] = t.regs[rn]
		return
	}
	if imm, ok := xref.OperandImm(inst, 1); ok {
		t.regs[rd] = xref.RegisterValue{Kind: xref.ValueImm, Addr: imm}
		return
	}
	t.regs[rd] = xref.RegisterValue{Kind: xref.ValueUnknown, Note: "indirect"}
}

func (t *cfArrayTracker) applyMoveKeep(inst *disassemble.Inst) {
	rd, ok := destRegIndex(inst)
	if !ok {
		return
	}
	imm, ok := xref.OperandImm(inst, 1)
	if !ok {
		t.regs[rd] = xref.RegisterValue{Kind: xref.ValueUnknown, Note: "indirect"}
		return
	}
	prev := t.regs[rd]
	if !prev.KnownAddress() {
		t.regs[rd] = xref.RegisterValue{Kind: xref.ValueUnknown, Note: prev.UnresolvedNote()}
		return
	}
	shift := uint64(0)
	if inst.NumOps > 1 && inst.Operands[1].ShiftValueUsed {
		shift = uint64(inst.Operands[1].ShiftValue)
	}
	mask := uint64(0xffff) << shift
	t.regs[rd] = xref.RegisterValue{Kind: prev.Kind, Addr: (prev.Addr &^ mask) | (imm & mask)}
}

func (t *cfArrayTracker) applyORRMove(inst *disassemble.Inst) bool {
	rd, ok := destRegIndex(inst)
	if !ok {
		return false
	}
	rn, rnOK := xref.OperandReg(inst, 1)
	rm, rmOK := xref.OperandReg(inst, 2)
	if rnOK && rmOK && isZeroReg(rn) {
		if idx, ok := xref.RegIndex(rm); ok {
			t.regs[rd] = t.regs[idx]
			return true
		}
	}
	return false
}

func (t *cfArrayTracker) clearDest(inst *disassemble.Inst, note string) {
	if rd, ok := destRegIndex(inst); ok {
		t.regs[rd] = xref.RegisterValue{Kind: xref.ValueUnknown, Note: note}
	}
}

func scanVirtualSlotCalls(scan functionScan, instrs []xref.Instruction) []Record {
	if len(scan.virtualSlots) == 0 {
		return nil
	}
	var records []Record
	for idx := range instrs {
		inst := &instrs[idx].Inst
		callReg, ok := indirectCallReg(inst)
		if !ok {
			continue
		}
		slot, receiver, ok := vtableSlotForCall(instrs, idx, callReg)
		if !ok || !isSelfRegister(receiver) {
			continue
		}
		targets := scan.virtualSlots[slot]
		if len(targets) == 0 {
			continue
		}
		state := xref.StateBefore(instrs, idx, scan.mem, xref.DefaultMaxInstructions)
		for _, target := range targets {
			value := ""
			if target.hasValue() {
				if v, _ := resolveRegister(state, target.ValueReg, scan.mem); v != "" {
					value = v
				}
			}
			for _, key := range resolveTargetKeys(state, target, scan.mem) {
				records = append(records, buildRecord(scan, inst.Address, target, key, value))
			}
		}
	}
	return records
}

func vtableSlotForCall(instrs []xref.Instruction, callIdx int, callReg disassemble.Register) (int, disassemble.Register, bool) {
	start := max(0, callIdx-6)
	for idx := callIdx - 1; idx >= start; idx-- {
		inst := &instrs[idx].Inst
		if !isLoadOp(inst.Operation) {
			continue
		}
		dst, ok := xref.OperandReg(inst, 0)
		if !ok || dst != callReg {
			continue
		}
		offset, ok := xref.MemoryOffset(inst, 1)
		if !ok || offset%8 != 0 {
			continue
		}
		baseReg, ok := xref.OperandReg(inst, 1)
		if !ok {
			continue
		}
		receiver, ok := vtableReceiverForBaseLoad(instrs, idx, baseReg)
		if !ok {
			continue
		}
		return int(offset / 8), receiver, true
	}
	return 0, disassemble.REG_NONE, false
}

func vtableReceiverForBaseLoad(instrs []xref.Instruction, slotLoadIdx int, baseReg disassemble.Register) (disassemble.Register, bool) {
	start := max(0, slotLoadIdx-6)
	for idx := slotLoadIdx - 1; idx >= start; idx-- {
		inst := &instrs[idx].Inst
		if !isLoadOp(inst.Operation) {
			continue
		}
		dst, ok := xref.OperandReg(inst, 0)
		if !ok || dst != baseReg {
			continue
		}
		offset, ok := xref.MemoryOffset(inst, 1)
		if !ok || offset != 0 {
			return disassemble.REG_NONE, false
		}
		return xref.OperandReg(inst, 1)
	}
	return disassemble.REG_NONE, false
}

func targetSetFromSpecs(targets map[uint64][]targetSpec) xref.TargetSet {
	addrs := make(xref.TargetSet, len(targets))
	for addr, specs := range targets {
		if len(specs) > 0 {
			addrs.Add(addr)
		}
	}
	return addrs
}

func resolveRegister(state xref.RegisterState, reg int, mem memoryReader) (string, string) {
	val, note := state.Register(reg)
	if note != "" {
		return "", note
	}
	if str, ok := resolveString(val.Addr, mem); ok {
		return str, ""
	}
	return "", "indirect"
}

func resolveTargetKeys(state xref.RegisterState, target targetSpec, mem memoryReader) []resolvedArg {
	val, note := state.Register(target.KeyReg)
	if note != "" {
		return []resolvedArg{{note: note}}
	}
	if target.KeyArray {
		if keys, ok := resolveStringArray(val.Addr, mem); ok {
			out := make([]resolvedArg, 0, len(keys))
			for _, key := range keys {
				out = append(out, resolvedArg{value: key})
			}
			return out
		}
		return []resolvedArg{{note: "cfarray_dynamic"}}
	}
	if str, ok := resolveString(val.Addr, mem); ok {
		return []resolvedArg{{value: str}}
	}
	return []resolvedArg{{note: "indirect"}}
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
		if strings, ok := resolveStringPointerArray(values, count, mem); ok {
			return strings, true
		}
	}
	for _, layout := range []struct {
		countOffset  uint64
		valuesOffset uint64
	}{
		{countOffset: 16, valuesOffset: 24},
		{countOffset: 24, valuesOffset: 32},
		{countOffset: 8, valuesOffset: 16},
	} {
		count, err := mem.ReadUint64(addr + layout.countOffset)
		if err != nil || count == 0 || count > 64 {
			continue
		}
		if strings, ok := resolveStringPointerArray(addr+layout.valuesOffset, count, mem); ok {
			return strings, true
		}
	}
	return nil, false
}

func resolveStringPointerArray(addr uint64, count uint64, mem memoryReader) ([]string, bool) {
	strings := make([]string, 0, count)
	for idx := range count {
		ptr, err := mem.ReadPointer(addr + idx*8)
		if err != nil || ptr == 0 {
			return nil, false
		}
		str, ok := resolveString(ptr, mem)
		if !ok {
			return nil, false
		}
		strings = append(strings, str)
	}
	return strings, true
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

func directCallTarget(inst *disassemble.Inst) (uint64, bool) {
	switch inst.Operation {
	case disassemble.ARM64_BL, disassemble.ARM64_B:
		return xref.LabelTarget(inst)
	default:
		return 0, false
	}
}

func indirectCallReg(inst *disassemble.Inst) (disassemble.Register, bool) {
	switch inst.Operation {
	case disassemble.ARM64_BLR, disassemble.ARM64_BLRAA, disassemble.ARM64_BLRAAZ,
		disassemble.ARM64_BLRAB, disassemble.ARM64_BLRABZ:
		return xref.OperandReg(inst, 0)
	default:
		return disassemble.REG_NONE, false
	}
}

func isCallOp(op disassemble.Operation) bool {
	switch op {
	case disassemble.ARM64_BL, disassemble.ARM64_BLR,
		disassemble.ARM64_BLRAA, disassemble.ARM64_BLRAAZ,
		disassemble.ARM64_BLRAB, disassemble.ARM64_BLRABZ:
		return true
	default:
		return false
	}
}

func isLoadOp(op disassemble.Operation) bool {
	switch op {
	case disassemble.ARM64_LDR, disassemble.ARM64_LDUR:
		return true
	default:
		return false
	}
}

func destRegIndex(inst *disassemble.Inst) (int, bool) {
	return xref.OperandRegIndex(inst, 0)
}

func isSP(reg disassemble.Register) bool {
	return reg == disassemble.REG_SP || reg == disassemble.REG_WSP
}

func isZeroReg(reg disassemble.Register) bool {
	return reg == disassemble.REG_XZR || reg == disassemble.REG_WZR
}

func isSelfRegister(reg disassemble.Register) bool {
	return reg == disassemble.REG_X0 || reg == disassemble.REG_W0
}

func shouldClearDestinationLocal(inst *disassemble.Inst) bool {
	if inst == nil || inst.NumOps == 0 {
		return false
	}
	if _, ok := destRegIndex(inst); !ok {
		return false
	}
	op := inst.Operation
	switch {
	case isCallOp(op):
		return false
	case op == disassemble.ARM64_B || op == disassemble.ARM64_BR ||
		op == disassemble.ARM64_BRAA || op == disassemble.ARM64_BRAAZ ||
		op == disassemble.ARM64_BRAB || op == disassemble.ARM64_BRABZ ||
		op == disassemble.ARM64_RET || op == disassemble.ARM64_RETAA || op == disassemble.ARM64_RETAB:
		return false
	}
	name := op.String()
	return !strings.HasPrefix(strings.ToLower(name), "st")
}
