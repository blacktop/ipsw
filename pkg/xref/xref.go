package xref

import (
	"encoding/binary"
	"strings"

	"github.com/blacktop/arm64-cgo/disassemble"
)

const DefaultMaxInstructions = 32

type MemoryReader interface {
	ReadPointer(addr uint64) (uint64, error)
}

type Mode uint8

const (
	ModeReferences Mode = iota
	ModeCalls
)

type ValueKind uint8

const (
	ValueUnknown ValueKind = iota
	ValueParam
	ValueAddr
	ValueImm
)

type RegisterValue struct {
	Kind ValueKind
	Addr uint64
	Note string
}

func (v RegisterValue) KnownAddress() bool {
	return v.Kind == ValueAddr || v.Kind == ValueImm
}

func (v RegisterValue) UnresolvedNote() string {
	if v.Note != "" {
		return v.Note
	}
	if v.Kind == ValueParam {
		return "param"
	}
	return "indirect"
}

type RegisterState [31]RegisterValue

func (s RegisterState) Register(reg int) (RegisterValue, string) {
	if reg < 0 || reg >= len(s) {
		return RegisterValue{}, "indirect"
	}
	val := s[reg]
	if val.Kind == ValueParam {
		return val, "param"
	}
	if !val.KnownAddress() {
		return val, val.UnresolvedNote()
	}
	return val, ""
}

type Instruction struct {
	disassemble.Inst
}

type TargetSet map[uint64]struct{}

func NewTargetSet(addrs ...uint64) TargetSet {
	targets := make(TargetSet, len(addrs))
	for _, addr := range addrs {
		targets.Add(addr)
	}
	return targets
}

func (s TargetSet) Add(addr uint64) {
	if addr != 0 {
		s[addr] = struct{}{}
	}
}

func (s TargetSet) Has(addr uint64) bool {
	_, ok := s[addr]
	return ok
}

type Options struct {
	Targets         TargetSet
	Reader          MemoryReader
	Mode            Mode
	ResolveIndirect bool
	MaxInstructions int
	FirstMatchOnly  bool
}

type Result struct {
	Address uint64
	Target  uint64
	Index   int
	Inst    disassemble.Inst
	State   RegisterState
}

type Scanner struct {
	decoder      disassemble.Decoder
	current      disassemble.Inst
	previous     disassemble.Inst
	instructions []Instruction
}

func ScanFunction(data []byte, start uint64, opts Options) []Result {
	if opts.Mode == ModeReferences && !opts.ResolveIndirect {
		var scanner Scanner
		return scanner.ScanFunction(data, start, opts)
	}
	return ScanInstructions(Decode(data, start), opts)
}

func ScanFirstFunction(data []byte, start uint64, opts Options) (Result, bool) {
	var scanner Scanner
	return scanner.ScanFirstFunction(data, start, opts)
}

func (s *Scanner) ScanFunction(data []byte, start uint64, opts Options) []Result {
	if opts.Mode == ModeReferences && !opts.ResolveIndirect {
		return s.scanReferenceBytes(data, start, opts)
	}
	return ScanInstructions(s.Decode(data, start), opts)
}

func (s *Scanner) Decode(data []byte, start uint64) []Instruction {
	s.instructions = decodeInto(s.instructions, data, start, &s.decoder)
	return s.instructions
}

func (s *Scanner) ScanFirstFunction(data []byte, start uint64, opts Options) (Result, bool) {
	if opts.Mode == ModeReferences && !opts.ResolveIndirect {
		return s.scanFirstReferenceBytes(data, start, opts)
	}
	opts.FirstMatchOnly = true
	results := s.ScanFunction(data, start, opts)
	if len(results) == 0 {
		return Result{}, false
	}
	return results[0], true
}

func ScanInstructions(instrs []Instruction, opts Options) []Result {
	if len(opts.Targets) == 0 {
		return nil
	}
	if opts.Mode == ModeCalls {
		return scanCalls(instrs, opts)
	}
	return scanReferences(instrs, opts)
}

func Decode(data []byte, start uint64) []Instruction {
	var decoder disassemble.Decoder
	return decodeInto(nil, data, start, &decoder)
}

func DecodeInto(dst []Instruction, data []byte, start uint64) []Instruction {
	var decoder disassemble.Decoder
	return decodeInto(dst, data, start, &decoder)
}

func decodeInto(dst []Instruction, data []byte, start uint64, decoder *disassemble.Decoder) []Instruction {
	out := dst[:0]
	if cap(out) < len(data)/4 {
		out = make([]Instruction, 0, len(data)/4)
	}
	for off := 0; off+4 <= len(data); off += 4 {
		raw := binary.LittleEndian.Uint32(data[off : off+4])
		addr := start + uint64(off)
		var inst disassemble.Inst
		if err := decoder.DecomposeInto(addr, raw, &inst); err == nil {
			out = append(out, Instruction{Inst: inst})
		}
	}
	return out
}

func MayContainDirectCallTarget(data []byte, start uint64, targets TargetSet) bool {
	for off := 0; off+4 <= len(data); off += 4 {
		raw := binary.LittleEndian.Uint32(data[off : off+4])
		target, ok := DirectBranchTarget(raw, start+uint64(off))
		if ok && targets.Has(target) {
			return true
		}
	}
	return false
}

func DirectBranchTarget(raw uint32, pc uint64) (uint64, bool) {
	switch raw & 0xfc000000 {
	case 0x14000000, 0x94000000:
	default:
		return 0, false
	}
	imm := int64(raw & 0x03ffffff)
	if imm&(1<<25) != 0 {
		imm |= ^int64(0x03ffffff)
	}
	return uint64(int64(pc) + (imm << 2)), true
}

func scanCalls(instrs []Instruction, opts Options) []Result {
	var results []Result
	for idx := range instrs {
		inst := &instrs[idx].Inst
		if target, ok := directCallTarget(inst); ok {
			if opts.Targets.Has(target) {
				results = append(results, Result{
					Address: inst.Address,
					Target:  target,
					Index:   idx,
					Inst:    *inst,
					State:   StateBefore(instrs, idx, opts.Reader, opts.MaxInstructions),
				})
				if opts.FirstMatchOnly {
					return results
				}
			}
			continue
		}
		if !opts.ResolveIndirect || !isIndirectBranch(inst.Operation) {
			continue
		}
		state := StateBefore(instrs, idx, opts.Reader, opts.MaxInstructions)
		if target, ok := indirectTarget(inst, state); ok && opts.Targets.Has(target) {
			results = append(results, Result{
				Address: inst.Address,
				Target:  target,
				Index:   idx,
				Inst:    *inst,
				State:   state,
			})
			if opts.FirstMatchOnly {
				return results
			}
		}
	}
	return results
}

func scanReferences(instrs []Instruction, opts Options) []Result {
	var results []Result
	for idx := range instrs {
		inst := &instrs[idx].Inst
		if target, ok := referenceTarget(instrs, idx); ok && opts.Targets.Has(target) {
			results = append(results, Result{
				Address: inst.Address,
				Target:  target,
				Index:   idx,
				Inst:    *inst,
			})
			if opts.FirstMatchOnly {
				return results
			}
			continue
		}
		if !opts.ResolveIndirect || !isIndirectBranch(inst.Operation) {
			continue
		}
		state := StateBefore(instrs, idx, opts.Reader, opts.MaxInstructions)
		if target, ok := indirectTarget(inst, state); ok && opts.Targets.Has(target) {
			results = append(results, Result{
				Address: inst.Address,
				Target:  target,
				Index:   idx,
				Inst:    *inst,
				State:   state,
			})
			if opts.FirstMatchOnly {
				return results
			}
		}
	}
	return results
}

func (s *Scanner) scanReferenceBytes(data []byte, start uint64, opts Options) []Result {
	if len(opts.Targets) == 0 {
		return nil
	}
	if opts.FirstMatchOnly {
		result, ok := s.scanFirstReferenceBytes(data, start, opts)
		if !ok {
			return nil
		}
		return []Result{result}
	}
	hasPrev := false
	var results []Result
	for off := 0; off+4 <= len(data); off += 4 {
		raw := binary.LittleEndian.Uint32(data[off : off+4])
		addr := start + uint64(off)
		if err := s.decoder.DecomposeInto(addr, raw, &s.current); err != nil {
			continue
		}
		if target, ok := referenceTargetWithPrev(&s.current, &s.previous, hasPrev); ok && opts.Targets.Has(target) {
			results = append(results, Result{
				Address: s.current.Address,
				Target:  target,
				Index:   off / 4,
				Inst:    s.current,
			})
		}
		s.previous = s.current
		hasPrev = true
	}
	return results
}

func (s *Scanner) scanFirstReferenceBytes(data []byte, start uint64, opts Options) (Result, bool) {
	if len(opts.Targets) == 0 {
		return Result{}, false
	}
	hasPrev := false
	for off := 0; off+4 <= len(data); off += 4 {
		raw := binary.LittleEndian.Uint32(data[off : off+4])
		addr := start + uint64(off)
		if err := s.decoder.DecomposeInto(addr, raw, &s.current); err != nil {
			continue
		}
		if target, ok := referenceTargetWithPrev(&s.current, &s.previous, hasPrev); ok && opts.Targets.Has(target) {
			return Result{
				Address: s.current.Address,
				Target:  target,
				Index:   off / 4,
				Inst:    s.current,
			}, true
		}
		s.previous = s.current
		hasPrev = true
	}
	return Result{}, false
}

func StateBefore(instrs []Instruction, callIndex int, mem MemoryReader, maxInstructions int) RegisterState {
	var state RegisterState
	for idx := range 8 {
		state[idx] = RegisterValue{Kind: ValueParam, Note: "param"}
	}
	window := maxInstructions
	if window <= 0 {
		window = DefaultMaxInstructions
	}
	start := max(callIndex-window, 0)
	for idx := start; idx < callIndex; idx++ {
		applyInstruction(&instrs[idx].Inst, state[:], mem)
	}
	return state
}

func directCallTarget(inst *disassemble.Inst) (uint64, bool) {
	switch inst.Operation {
	case disassemble.ARM64_BL, disassemble.ARM64_B:
		return LabelTarget(inst)
	default:
		return 0, false
	}
}

func referenceTarget(instrs []Instruction, idx int) (uint64, bool) {
	inst := &instrs[idx].Inst
	if idx == 0 {
		return referenceTargetWithPrev(inst, nil, false)
	}
	return referenceTargetWithPrev(inst, &instrs[idx-1].Inst, true)
}

func referenceTargetWithPrev(inst *disassemble.Inst, prev *disassemble.Inst, hasPrev bool) (uint64, bool) {
	if isBranchReferenceOp(inst.Operation) {
		return LabelTarget(inst)
	}
	if isLoadLiteral(inst) {
		return OperandImm(inst, 1)
	}
	if !hasPrev || prev == nil {
		return 0, false
	}
	if prev.Operation != disassemble.ARM64_ADRP {
		return 0, false
	}
	switch inst.Operation {
	case disassemble.ARM64_ADD, disassemble.ARM64_LDR, disassemble.ARM64_LDRB,
		disassemble.ARM64_LDRSW, disassemble.ARM64_STRB:
	default:
		return 0, false
	}
	adrpReg, ok := OperandReg(prev, 0)
	if !ok {
		return 0, false
	}
	adrpImm, ok := OperandImm(prev, 1)
	if !ok {
		return 0, false
	}
	srcReg, ok := OperandReg(inst, 1)
	if !ok || adrpReg != srcReg {
		return 0, false
	}
	switch inst.Operation {
	case disassemble.ARM64_ADD:
		imm, ok := OperandImm(inst, 2)
		if !ok {
			return 0, false
		}
		return adrpImm + imm, true
	default:
		imm, ok := MemoryOffset(inst, 1)
		if !ok {
			return 0, false
		}
		return adrpImm + imm, true
	}
}

func indirectTarget(inst *disassemble.Inst, state RegisterState) (uint64, bool) {
	reg, ok := OperandReg(inst, 0)
	if !ok {
		return 0, false
	}
	idx, ok := RegIndex(reg)
	if !ok {
		return 0, false
	}
	val := state[idx]
	if val.KnownAddress() && val.Addr != 0 {
		return val.Addr, true
	}
	return 0, false
}

func applyInstruction(inst *disassemble.Inst, state []RegisterValue, mem MemoryReader) {
	switch inst.Operation {
	case disassemble.ARM64_ADR, disassemble.ARM64_ADRP:
		if rd, ok := destRegIndex(inst); ok {
			if imm, ok := OperandImm(inst, 1); ok {
				state[rd] = RegisterValue{Kind: ValueAddr, Addr: imm}
			}
		}
	case disassemble.ARM64_ADD:
		applyAdd(inst, state)
	case disassemble.ARM64_LDR, disassemble.ARM64_LDUR:
		applyLoad(inst, state, mem)
	case disassemble.ARM64_LDNP, disassemble.ARM64_LDP, disassemble.ARM64_LDPSW:
		clearOperandDest(inst, state, 0, "indirect")
		clearOperandDest(inst, state, 1, "indirect")
	case disassemble.ARM64_MOV:
		applyMove(inst, state)
	case disassemble.ARM64_MOVZ:
		if rd, ok := destRegIndex(inst); ok {
			if imm, ok := OperandImm(inst, 1); ok {
				state[rd] = RegisterValue{Kind: ValueImm, Addr: imm}
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
}

func applyAdd(inst *disassemble.Inst, state []RegisterValue) {
	rd, ok := destRegIndex(inst)
	if !ok {
		return
	}
	rn, ok := OperandRegIndex(inst, 1)
	if !ok {
		state[rd] = RegisterValue{Kind: ValueUnknown, Note: "indirect"}
		return
	}
	imm, ok := OperandImm(inst, 2)
	if !ok {
		state[rd] = RegisterValue{Kind: ValueUnknown, Note: "indirect"}
		return
	}
	base := state[rn]
	if base.KnownAddress() {
		state[rd] = RegisterValue{Kind: base.Kind, Addr: base.Addr + imm}
		return
	}
	state[rd] = RegisterValue{Kind: ValueUnknown, Note: base.UnresolvedNote()}
}

func applyLoad(inst *disassemble.Inst, state []RegisterValue, mem MemoryReader) {
	rd, ok := destRegIndex(inst)
	if !ok {
		return
	}
	if target, ok := LabelTarget(inst); ok {
		state[rd] = readPointerValue(mem, target)
		return
	}
	baseReg, ok := OperandRegIndex(inst, 1)
	if !ok {
		state[rd] = RegisterValue{Kind: ValueUnknown, Note: "indirect"}
		return
	}
	base := state[baseReg]
	if !base.KnownAddress() {
		state[rd] = RegisterValue{Kind: ValueUnknown, Note: base.UnresolvedNote()}
		return
	}
	access, ok := memoryAccess(inst, 1)
	if !ok {
		state[rd] = RegisterValue{Kind: ValueUnknown, Note: "indirect"}
		return
	}
	state[rd] = readPointerValue(mem, base.Addr+access.readOffset)
	if access.writeback && baseReg != rd {
		state[baseReg] = RegisterValue{Kind: base.Kind, Addr: base.Addr + access.writeOffset}
	}
}

func readPointerValue(mem MemoryReader, addr uint64) RegisterValue {
	if mem == nil {
		return RegisterValue{Kind: ValueUnknown, Note: "indirect"}
	}
	ptr, err := mem.ReadPointer(addr)
	if err != nil || ptr == 0 {
		return RegisterValue{Kind: ValueUnknown, Note: "indirect"}
	}
	return RegisterValue{Kind: ValueAddr, Addr: ptr}
}

func applyMove(inst *disassemble.Inst, state []RegisterValue) {
	rd, ok := destRegIndex(inst)
	if !ok {
		return
	}
	if rn, ok := OperandRegIndex(inst, 1); ok {
		state[rd] = state[rn]
		return
	}
	if imm, ok := OperandImm(inst, 1); ok {
		state[rd] = RegisterValue{Kind: ValueImm, Addr: imm}
		return
	}
	state[rd] = RegisterValue{Kind: ValueUnknown, Note: "indirect"}
}

func applyMoveKeep(inst *disassemble.Inst, state []RegisterValue) {
	rd, ok := destRegIndex(inst)
	if !ok {
		return
	}
	imm, ok := OperandImm(inst, 1)
	if !ok {
		state[rd] = RegisterValue{Kind: ValueUnknown, Note: "indirect"}
		return
	}
	prev := state[rd]
	if !prev.KnownAddress() {
		state[rd] = RegisterValue{Kind: ValueUnknown, Note: prev.UnresolvedNote()}
		return
	}
	shift := uint64(0)
	if inst.NumOps > 1 && inst.Operands[1].ShiftValueUsed {
		shift = uint64(inst.Operands[1].ShiftValue)
	}
	mask := uint64(0xffff) << shift
	state[rd] = RegisterValue{Kind: prev.Kind, Addr: (prev.Addr &^ mask) | (imm & mask)}
}

func applyORRMove(inst *disassemble.Inst, state []RegisterValue) bool {
	rd, ok := destRegIndex(inst)
	if !ok {
		return false
	}
	rn, rnOK := OperandReg(inst, 1)
	rm, rmOK := OperandReg(inst, 2)
	if rnOK && rmOK && isZeroReg(rn) {
		if idx, ok := RegIndex(rm); ok {
			state[rd] = state[idx]
			return true
		}
	}
	return false
}

func StubPointerSlotsFromInstructions(instrs []Instruction) map[uint64]uint64 {
	slots := make(map[uint64]uint64)
	for idx := range instrs {
		if stub, slot, ok := stubPointerSlot(instrs, idx); ok {
			slots[stub] = slot
		}
	}
	return slots
}

func stubPointerSlot(instrs []Instruction, idx int) (uint64, uint64, bool) {
	if stub, slot, ok := adrpAddLDRStubSlot(instrs, idx); ok {
		return stub, slot, true
	}
	return adrpLDRStubSlot(instrs, idx)
}

func adrpAddLDRStubSlot(instrs []Instruction, idx int) (uint64, uint64, bool) {
	if idx < 2 {
		return 0, 0, false
	}
	adrp := &instrs[idx-2].Inst
	add := &instrs[idx-1].Inst
	ldr := &instrs[idx].Inst
	if adrp.Operation != disassemble.ARM64_ADRP ||
		add.Operation != disassemble.ARM64_ADD ||
		ldr.Operation != disassemble.ARM64_LDR {
		return 0, 0, false
	}
	adrpReg, ok := OperandReg(adrp, 0)
	if !ok {
		return 0, 0, false
	}
	addDst, ok := OperandReg(add, 0)
	if !ok || addDst != adrpReg {
		return 0, 0, false
	}
	addBase, ok := OperandReg(add, 1)
	if !ok || addBase != adrpReg {
		return 0, 0, false
	}
	ldrBase, ok := OperandReg(ldr, 1)
	if !ok || ldrBase != addDst {
		return 0, 0, false
	}
	base, ok := OperandImm(adrp, 1)
	if !ok {
		return 0, 0, false
	}
	addImm, ok := OperandImm(add, 2)
	if !ok {
		return 0, 0, false
	}
	ldrImm, ok := MemoryOffset(ldr, 1)
	if !ok {
		return 0, 0, false
	}
	return adrp.Address, base + addImm + ldrImm, true
}

func adrpLDRStubSlot(instrs []Instruction, idx int) (uint64, uint64, bool) {
	if idx < 1 {
		return 0, 0, false
	}
	adrp := &instrs[idx-1].Inst
	ldr := &instrs[idx].Inst
	if adrp.Operation != disassemble.ARM64_ADRP || ldr.Operation != disassemble.ARM64_LDR {
		return 0, 0, false
	}
	adrpReg, ok := OperandReg(adrp, 0)
	if !ok {
		return 0, 0, false
	}
	ldrDst, ok := OperandReg(ldr, 0)
	if !ok || ldrDst != adrpReg {
		return 0, 0, false
	}
	ldrBase, ok := OperandReg(ldr, 1)
	if !ok || ldrBase != adrpReg {
		return 0, 0, false
	}
	base, ok := OperandImm(adrp, 1)
	if !ok {
		return 0, 0, false
	}
	ldrImm, ok := MemoryOffset(ldr, 1)
	if !ok {
		return 0, 0, false
	}
	return adrp.Address, base + ldrImm, true
}

func LabelTarget(inst *disassemble.Inst) (uint64, bool) {
	for idx := 0; idx < int(inst.NumOps); idx++ {
		op := &inst.Operands[idx]
		if op.Class == disassemble.LABEL {
			return op.GetImmediate(), true
		}
	}
	return 0, false
}

func OperandReg(inst *disassemble.Inst, idx int) (disassemble.Register, bool) {
	if inst == nil || int(inst.NumOps) <= idx || inst.Operands[idx].NumRegisters == 0 {
		return disassemble.REG_NONE, false
	}
	return inst.Operands[idx].Registers[0], true
}

func OperandRegIndex(inst *disassemble.Inst, idx int) (int, bool) {
	reg, ok := OperandReg(inst, idx)
	if !ok {
		return 0, false
	}
	return RegIndex(reg)
}

func OperandImm(inst *disassemble.Inst, idx int) (uint64, bool) {
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

type memoryAccessInfo struct {
	readOffset  uint64
	writeOffset uint64
	writeback   bool
}

func MemoryOffset(inst *disassemble.Inst, idx int) (uint64, bool) {
	access, ok := memoryAccess(inst, idx)
	return access.readOffset, ok
}

func MemoryAccess(inst *disassemble.Inst, idx int) (uint64, uint64, bool, bool) {
	access, ok := memoryAccess(inst, idx)
	if !ok {
		return 0, 0, false, false
	}
	return access.readOffset, access.writeOffset, access.writeback, true
}

func memoryAccess(inst *disassemble.Inst, idx int) (memoryAccessInfo, bool) {
	if inst == nil || int(inst.NumOps) <= idx {
		return memoryAccessInfo{}, false
	}
	op := &inst.Operands[idx]
	switch op.Class {
	case disassemble.MEM_OFFSET:
		return memoryAccessInfo{readOffset: op.GetImmediate()}, true
	case disassemble.MEM_PRE_IDX:
		imm := op.GetImmediate()
		return memoryAccessInfo{readOffset: imm, writeOffset: imm, writeback: true}, true
	case disassemble.MEM_POST_IDX:
		return memoryAccessInfo{writeOffset: op.GetImmediate(), writeback: true}, true
	default:
		return memoryAccessInfo{}, false
	}
}

func RegIndex(reg disassemble.Register) (int, bool) {
	switch {
	case reg >= disassemble.REG_X0 && reg <= disassemble.REG_X30:
		return int(reg - disassemble.REG_X0), true
	case reg >= disassemble.REG_W0 && reg <= disassemble.REG_W30:
		return int(reg - disassemble.REG_W0), true
	default:
		return 0, false
	}
}

func destRegIndex(inst *disassemble.Inst) (int, bool) {
	return OperandRegIndex(inst, 0)
}

func isZeroReg(reg disassemble.Register) bool {
	return reg == disassemble.REG_XZR || reg == disassemble.REG_WZR
}

func clearDest(inst *disassemble.Inst, state []RegisterValue, note string) {
	clearOperandDest(inst, state, 0, note)
}

func clearOperandDest(inst *disassemble.Inst, state []RegisterValue, operand int, note string) {
	if rd, ok := OperandRegIndex(inst, operand); ok {
		state[rd] = RegisterValue{Kind: ValueUnknown, Note: note}
	}
}

func clearVolatile(state []RegisterValue) {
	for idx := 0; idx <= 17 && idx < len(state); idx++ {
		state[idx] = RegisterValue{Kind: ValueUnknown, Note: "indirect"}
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

func isIndirectBranch(op disassemble.Operation) bool {
	switch op {
	case disassemble.ARM64_BLR, disassemble.ARM64_BLRAA, disassemble.ARM64_BLRAAZ,
		disassemble.ARM64_BLRAB, disassemble.ARM64_BLRABZ,
		disassemble.ARM64_BR, disassemble.ARM64_BRAA, disassemble.ARM64_BRAAZ,
		disassemble.ARM64_BRAB, disassemble.ARM64_BRABZ:
		return true
	default:
		return false
	}
}

func isBranchReferenceOp(op disassemble.Operation) bool {
	switch op {
	case disassemble.ARM64_B, disassemble.ARM64_BL,
		disassemble.ARM64_CBZ, disassemble.ARM64_CBNZ,
		disassemble.ARM64_TBZ, disassemble.ARM64_TBNZ,
		disassemble.ARM64_B_EQ, disassemble.ARM64_B_NE,
		disassemble.ARM64_B_CS, disassemble.ARM64_B_CC,
		disassemble.ARM64_B_MI, disassemble.ARM64_B_PL,
		disassemble.ARM64_B_VS, disassemble.ARM64_B_VC,
		disassemble.ARM64_B_HI, disassemble.ARM64_B_LS,
		disassemble.ARM64_B_GE, disassemble.ARM64_B_LT,
		disassemble.ARM64_B_GT, disassemble.ARM64_B_LE,
		disassemble.ARM64_B_AL, disassemble.ARM64_B_NV:
		return true
	default:
		return false
	}
}

func isLoadLiteral(inst *disassemble.Inst) bool {
	switch inst.Operation {
	case disassemble.ARM64_LDR, disassemble.ARM64_LDRSW, disassemble.ARM64_PRFM:
		return inst != nil && inst.NumOps > 1 && inst.Operands[1].Class == disassemble.LABEL
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
	if isBranchReferenceOp(inst.Operation) {
		return false
	}
	return true
}
