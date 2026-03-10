package cpp

import (
	"fmt"

	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/go-macho"
)

type microTag uint16

const (
	microTagBL microTag = 1 << iota
	microTagB
	microTagRET
	microTagADRP
	microTagADR
	microTagStoreToX0
	microTagX16Candidate
)

type microPlan struct {
	anchorBLOffsets     []int
	branchEventOffsets  []int
	retOffsets          []int
	x16CandidateOffsets []int
	storeToX0Offsets    []int
	maxOffset           int

	tags    []microTag
	targets []uint64
}

type microState struct {
	owner     *macho.File
	funcStart uint64
	pc        uint64
	sp        uint64

	regs        [31]uint64
	regKnown    [31]bool
	regBase     [31]uint64
	regLoadAddr [31]uint64
	spills      [4]trackedSpill
	stackSlots  map[uint64]uint64

	x16Candidate uint64
}

type microMemAccess struct {
	addr           uint64
	baseIdx        int
	baseIsSP       bool
	writeBack      bool
	writeBackAfter bool
	newBase        uint64
}

func newMicroState(owner *macho.File, funcStart uint64) *microState {
	return &microState{
		owner:     owner,
		funcStart: funcStart,
		sp:        0x7fff00000000,
	}
}

func (s *microState) GetX(reg int) uint64 {
	if reg < 0 || reg >= len(s.regs) {
		return 0
	}
	return s.regs[reg]
}

func (s *microState) SetX(reg int, value uint64) {
	if reg < 0 || reg >= len(s.regs) {
		return
	}
	s.regs[reg] = value
	s.regKnown[reg] = true
	s.regBase[reg] = 0
	s.regLoadAddr[reg] = 0
}

func (s *microState) GetSP() uint64 {
	return s.sp
}

func (s *microState) ReadUint64(addr uint64) (uint64, error) {
	if value, ok := s.stackSlots[addr]; ok {
		return value, nil
	}
	return 0, fmt.Errorf("address %#x not mapped in micro stack", addr)
}

func (s *microState) writeStack(addr uint64, value uint64) {
	if s.stackSlots == nil {
		s.stackSlots = make(map[uint64]uint64, 8)
	}
	s.stackSlots[addr] = value
}

func (s *microState) clearTracked(idx int) {
	if idx < 0 || idx >= len(s.regs) {
		return
	}
	s.regs[idx] = 0
	s.regKnown[idx] = false
	s.regBase[idx] = 0
	s.regLoadAddr[idx] = 0
}

func (s *microState) copyTracked(dst, src int) {
	if dst < 0 || dst >= len(s.regs) || src < 0 || src >= len(s.regs) {
		return
	}
	s.regs[dst] = s.regs[src]
	s.regKnown[dst] = s.regKnown[src]
	s.regBase[dst] = s.regBase[src]
	s.regLoadAddr[dst] = s.regLoadAddr[src]
}

func (s *microState) setKnownValue(idx int, value uint64) {
	if idx < 0 || idx >= len(s.regs) {
		return
	}
	s.regs[idx] = value
	s.regKnown[idx] = true
	s.regBase[idx] = 0
	s.regLoadAddr[idx] = 0
}

func (s *microState) setKnownBase(idx int, value uint64) {
	if idx < 0 || idx >= len(s.regs) {
		return
	}
	s.regs[idx] = value
	s.regKnown[idx] = true
	s.regBase[idx] = value
	s.regLoadAddr[idx] = 0
}

func recoveredTrackedValue(state *microState, reg int, allowBase bool) uint64 {
	value := recoverSpilledRegister(state, &state.spills, reg)
	if value != 0 || (reg >= 0 && reg < len(state.regKnown) && state.regKnown[reg]) {
		return value
	}
	if allowBase && reg >= 0 && reg < len(state.regBase) && state.regBase[reg] != 0 {
		return state.regBase[reg]
	}
	return 0
}

func isReturnInstruction(raw uint32) bool {
	switch raw {
	case 0xd65f03c0, 0xd65f0fff, 0xd65f0bff:
		return true
	default:
		return false
	}
}

func isCallRegisterRaw(raw uint32) bool {
	return (raw & 0xfffffc1f) == 0xd63f0000
}

func isStoreToX0Raw(raw uint32) bool {
	switch {
	case raw&0xffffffe0 == 0xf9000000:
		return true // STR Xt, [x0]
	case raw&0xffffffe0 == 0xf8000000:
		return true // STUR Xt, [x0]
	case (raw & 0xffc003e0) == 0xa9000000:
		return true // STP Xt1, Xt2, [x0]
	default:
		return false
	}
}

func isPotentialX16Write(raw uint32) bool {
	switch {
	case (raw & 0x9f00001f) == 0x90000010:
		return true // ADRP X16, ...
	case (raw & 0x9f00001f) == 0x10000010:
		return true // ADR X16, ...
	case (raw & 0xff8003ff) == 0x91000210:
		return true // ADD X16, X16, #imm (best-effort immediate form)
	case (raw & 0xfffffc1f) == 0xf9400210:
		return true // LDR X16, [X16, #imm]
	case (raw & 0xfffffc1f) == 0xf8400210:
		return true // LDUR X16, [X16, #imm]
	case (raw & 0xfffffc1f) == 0xaa000010:
		return true // MOV/ORR into X16
	case (raw & 0xff80001f) == 0xd2800010:
		return true // MOVZ X16, #imm
	case (raw & 0xff80001f) == 0x92800010:
		return true // MOVN X16, #imm
	case (raw & 0xff80001f) == 0xf2800010:
		return true // MOVK X16, #imm
	default:
		return isPACLikeX16(raw)
	}
}

func isPACLikeX16(raw uint32) bool {
	switch {
	case raw == 0xd503211f, raw == 0xd503215f:
		return true // PACIA1716 / PACIB1716
	case (raw & 0xfffffc1f) == 0xdac10010,
		(raw & 0xfffffc1f) == 0xdac10410,
		(raw & 0xfffffc1f) == 0xdac10810,
		(raw & 0xfffffc1f) == 0xdac10c10:
		return true // PACIA/PACIB/PACDA/PACDB X16, Xn
	case raw == 0xdac123f0, raw == 0xdac127f0:
		return true // PACIZA/PACIZB X16
	default:
		return false
	}
}

func isPACOperation(op disassemble.Operation) bool {
	switch op {
	case disassemble.ARM64_PACDA,
		disassemble.ARM64_PACIA,
		disassemble.ARM64_PACIA1716,
		disassemble.ARM64_PACIA171615,
		disassemble.ARM64_PACIASP,
		disassemble.ARM64_PACIASPPC,
		disassemble.ARM64_PACIAZ,
		disassemble.ARM64_PACDB,
		disassemble.ARM64_PACDZA,
		disassemble.ARM64_PACDZB,
		disassemble.ARM64_PACIB,
		disassemble.ARM64_PACIB1716,
		disassemble.ARM64_PACIB171615,
		disassemble.ARM64_PACIBSP,
		disassemble.ARM64_PACIBSPPC,
		disassemble.ARM64_PACIBZ,
		disassemble.ARM64_PACIZA,
		disassemble.ARM64_PACIZB:
		return true
	default:
		return false
	}
}

func isCallLikeOperation(op disassemble.Operation) bool {
	switch op {
	case disassemble.ARM64_BL,
		disassemble.ARM64_BLR,
		disassemble.ARM64_BLRAA,
		disassemble.ARM64_BLRAAZ,
		disassemble.ARM64_BLRAB,
		disassemble.ARM64_BLRABZ:
		return true
	default:
		return false
	}
}

func isConditionalBranchOperation(op disassemble.Operation) bool {
	switch op {
	case disassemble.ARM64_CBZ,
		disassemble.ARM64_CBNZ,
		disassemble.ARM64_TBZ,
		disassemble.ARM64_TBNZ,
		disassemble.ARM64_B_AL,
		disassemble.ARM64_B_CC,
		disassemble.ARM64_B_CS,
		disassemble.ARM64_B_EQ,
		disassemble.ARM64_B_GE,
		disassemble.ARM64_B_GT,
		disassemble.ARM64_B_HI,
		disassemble.ARM64_B_LE,
		disassemble.ARM64_B_LS,
		disassemble.ARM64_B_LT,
		disassemble.ARM64_B_MI,
		disassemble.ARM64_B_NE,
		disassemble.ARM64_B_NV,
		disassemble.ARM64_B_PL,
		disassemble.ARM64_B_VC,
		disassemble.ARM64_B_VS:
		return true
	default:
		return false
	}
}

func is32BitReg(reg disassemble.Register) bool {
	return reg >= disassemble.REG_W0 && reg <= disassemble.REG_W30
}

func normalizeRegWrite(reg disassemble.Register, value uint64) uint64 {
	if is32BitReg(reg) {
		return uint64(uint32(value))
	}
	return value
}

func buildMicroPlan(start uint64, data []byte, isAnchor func(uint64) bool, maxOffset int) microPlan {
	count := len(data) / 4
	plan := microPlan{
		tags:    make([]microTag, count),
		targets: make([]uint64, count),
	}
	for off := 0; off+4 <= len(data); off += 4 {
		raw := readUint32At(data, off)
		idx := off / 4
		switch {
		case (raw & 0x9f000000) == 0x90000000:
			plan.tags[idx] |= microTagADRP
		case (raw & 0x9f000000) == 0x10000000:
			plan.tags[idx] |= microTagADR
		}
		if target, ok := decodeBLTarget(start+uint64(off), raw); ok {
			plan.tags[idx] |= microTagBL
			plan.targets[idx] = target
			plan.branchEventOffsets = append(plan.branchEventOffsets, off)
			if isAnchor != nil && isAnchor(target) {
				plan.anchorBLOffsets = append(plan.anchorBLOffsets, off)
			}
		} else if target, ok := decodeBTarget(start+uint64(off), raw); ok {
			plan.tags[idx] |= microTagB
			plan.targets[idx] = target
			plan.branchEventOffsets = append(plan.branchEventOffsets, off)
		} else if isCallRegisterRaw(raw) {
			plan.branchEventOffsets = append(plan.branchEventOffsets, off)
		}
		if isReturnInstruction(raw) {
			plan.tags[idx] |= microTagRET
			plan.retOffsets = append(plan.retOffsets, off)
		}
		if isPotentialX16Write(raw) {
			plan.tags[idx] |= microTagX16Candidate
			plan.x16CandidateOffsets = append(plan.x16CandidateOffsets, off)
		}
		if isStoreToX0Raw(raw) {
			plan.tags[idx] |= microTagStoreToX0
			plan.storeToX0Offsets = append(plan.storeToX0Offsets, off)
		}
	}
	plan.maxOffset = len(data) - 4
	if maxOffset >= 0 && maxOffset < plan.maxOffset {
		plan.maxOffset = maxOffset
	}
	if plan.maxOffset < 0 {
		plan.maxOffset = 0
	}
	return plan
}

func branchTargetFromState(state *microState, inst *disassemble.Inst) (uint64, bool) {
	if inst == nil || operandCount(inst) == 0 {
		return 0, false
	}
	reg, ok := operandRegister(&inst.Operands[0], 0)
	if !ok {
		return 0, false
	}
	switch inst.Operation {
	case disassemble.ARM64_BR,
		disassemble.ARM64_BRAA,
		disassemble.ARM64_BRAAZ,
		disassemble.ARM64_BRAB,
		disassemble.ARM64_BRABZ:
		if idx, ok := registerToIndex(reg); ok {
			return state.GetX(idx), true
		}
	}
	return 0, false
}

func localBranchOffset(funcStart uint64, dataLen int, maxOffset int, target uint64) (int, bool) {
	if target < funcStart || target >= funcStart+uint64(dataLen) {
		return 0, false
	}
	off := int(target - funcStart)
	if off < 0 || off > maxOffset || off%4 != 0 {
		return 0, false
	}
	return off, true
}

func (s *microState) memoryAccess(op *disassemble.Op) (microMemAccess, bool) {
	if op == nil {
		return microMemAccess{}, false
	}
	if op.Class == disassemble.LABEL {
		return microMemAccess{addr: op.GetImmediate()}, true
	}
	baseReg, ok := operandRegister(op, 0)
	if !ok {
		return microMemAccess{}, false
	}

	var base uint64
	access := microMemAccess{baseIdx: -1}
	switch baseReg {
	case disassemble.REG_SP:
		base = s.sp
		access.baseIsSP = true
	default:
		idx, ok := registerToIndex(baseReg)
		if !ok || idx >= len(s.regs) {
			return microMemAccess{}, false
		}
		base = s.regs[idx]
		access.baseIdx = idx
	}

	switch op.Class {
	case disassemble.MEM_OFFSET:
		addr, ok := addSignedOffset(base, int64(op.GetImmediate()))
		if !ok {
			return microMemAccess{}, false
		}
		access.addr = addr
		return access, true
	case disassemble.MEM_PRE_IDX:
		addr, ok := addSignedOffset(base, int64(op.GetImmediate()))
		if !ok {
			return microMemAccess{}, false
		}
		access.addr = addr
		access.newBase = addr
		access.writeBack = true
		return access, true
	case disassemble.MEM_POST_IDX:
		newBase, ok := addSignedOffset(base, int64(op.GetImmediate()))
		if !ok {
			return microMemAccess{}, false
		}
		access.addr = base
		access.newBase = newBase
		access.writeBack = true
		access.writeBackAfter = true
		return access, true
	default:
		return microMemAccess{}, false
	}
}

func (s *microState) applyMemWriteBack(access microMemAccess) {
	if !access.writeBack {
		return
	}
	if access.baseIsSP {
		s.sp = access.newBase
		return
	}
	if access.baseIdx >= 0 {
		s.setKnownValue(access.baseIdx, access.newBase)
	}
}

func (s *microState) resetCallEvidence() {
	s.regLoadAddr = [31]uint64{}
	s.spills = [4]trackedSpill{}
	s.x16Candidate = 0
}

func (s *microState) classifyStore(inst *disassemble.Inst) (microMemAccess, [2]int, int, bool) {
	var src [2]int
	for i := range src {
		src[i] = -1
	}
	if inst == nil {
		return microMemAccess{}, src, 0, false
	}
	switch inst.Operation {
	case disassemble.ARM64_STR, disassemble.ARM64_STUR:
		reg, ok := operandRegister(&inst.Operands[0], 0)
		if operandCount(inst) < 2 || !ok {
			return microMemAccess{}, src, 0, false
		}
		access, ok := s.memoryAccess(&inst.Operands[1])
		if !ok {
			return microMemAccess{}, src, 0, false
		}
		if idx, ok := registerToIndex(reg); ok {
			src[0] = idx
			return access, src, 1, true
		}
	case disassemble.ARM64_STP:
		if operandCount(inst) < 3 {
			return microMemAccess{}, src, 0, false
		}
		access, ok := s.memoryAccess(&inst.Operands[2])
		if !ok {
			return microMemAccess{}, src, 0, false
		}
		count := 0
		if reg, ok := operandRegister(&inst.Operands[0], 0); ok {
			if idx, ok := registerToIndex(reg); ok {
				src[0] = idx
				count++
			}
		}
		if reg, ok := operandRegister(&inst.Operands[1], 0); ok {
			if idx, ok := registerToIndex(reg); ok {
				src[1] = idx
				count++
			}
		}
		return access, src, count, count > 0
	}
	return microMemAccess{}, src, 0, false
}

func (s *Scanner) loadValueAt(owner *macho.File, state *microState, addr uint64) (uint64, bool) {
	if value, ok := state.stackSlots[addr]; ok {
		return value, true
	}
	if ptr, ok := s.resolvePointerAt(owner, addr); ok {
		return ptr, true
	}
	return 0, false
}

func (s *Scanner) trackedLoadAddress(state *microState, op *disassemble.Op) (microMemAccess, bool) {
	if op == nil {
		return microMemAccess{}, false
	}
	if op.Class == disassemble.LABEL {
		return microMemAccess{addr: op.GetImmediate()}, true
	}
	baseReg, ok := operandRegister(op, 0)
	if !ok {
		return microMemAccess{}, false
	}

	switch baseReg {
	case disassemble.REG_SP:
		return state.memoryAccess(op)
	}

	baseIdx, ok := registerToIndex(baseReg)
	if !ok || baseIdx >= len(state.regBase) || state.regBase[baseIdx] == 0 {
		return microMemAccess{}, false
	}

	base := state.regBase[baseIdx]
	access := microMemAccess{baseIdx: baseIdx}
	switch op.Class {
	case disassemble.MEM_OFFSET:
		addr, ok := addSignedOffset(base, int64(op.GetImmediate()))
		if !ok {
			return microMemAccess{}, false
		}
		access.addr = addr
		return access, true
	case disassemble.MEM_PRE_IDX:
		addr, ok := addSignedOffset(base, int64(op.GetImmediate()))
		if !ok {
			return microMemAccess{}, false
		}
		access.addr = addr
		access.newBase = addr
		access.writeBack = true
		return access, true
	case disassemble.MEM_POST_IDX:
		newBase, ok := addSignedOffset(base, int64(op.GetImmediate()))
		if !ok {
			return microMemAccess{}, false
		}
		access.addr = base
		access.newBase = newBase
		access.writeBack = true
		access.writeBackAfter = true
		return access, true
	default:
		return microMemAccess{}, false
	}
}

func (s *Scanner) applyMicroInstruction(state *microState, inst *disassemble.Inst) {
	if inst == nil {
		return
	}

	captureRegisterSpills(state, inst, &state.spills)
	handled := true

	switch inst.Operation {
	case disassemble.ARM64_ADRP:
		if reg, ok := operandRegister(&inst.Operands[0], 0); operandCount(inst) > 0 && ok {
			if idx, ok := registerToIndex(reg); ok {
				if addr, ok := decodeADRPImmediate(inst.Address, inst.Raw); ok {
					s.stateWriteAddress(state, idx, addr)
				} else {
					state.clearTracked(idx)
				}
			}
		}
	case disassemble.ARM64_ADR:
		if reg, ok := operandRegister(&inst.Operands[0], 0); operandCount(inst) > 1 && ok {
			if idx, ok := registerToIndex(reg); ok {
				s.stateWriteAddress(state, idx, inst.Operands[1].GetImmediate())
			}
		}
	case disassemble.ARM64_ADD:
		s.applyMicroAdd(state, inst)
	case disassemble.ARM64_SUB:
		s.applyMicroSub(state, inst)
	case disassemble.ARM64_MOV:
		s.applyMicroMov(state, inst)
	case disassemble.ARM64_MOVZ:
		s.applyMicroMovWide(state, inst, false, false)
	case disassemble.ARM64_MOVN:
		s.applyMicroMovWide(state, inst, true, false)
	case disassemble.ARM64_MOVK:
		s.applyMicroMovWide(state, inst, false, true)
	case disassemble.ARM64_ORR:
		s.applyMicroOrr(state, inst)
	case disassemble.ARM64_LDR, disassemble.ARM64_LDUR:
		s.applyMicroLoad(state, inst, false)
	case disassemble.ARM64_LDP:
		s.applyMicroLoad(state, inst, true)
	case disassemble.ARM64_STR, disassemble.ARM64_STUR:
		s.applyMicroStore(state, inst, false)
	case disassemble.ARM64_STP:
		s.applyMicroStore(state, inst, true)
	default:
		handled = false
	}

	if !handled {
		s.invalidateUnsupportedDestinations(state, inst)
	}
	if isPACOperation(inst.Operation) && operandCount(inst) > 0 && operandHasRegister(&inst.Operands[0], disassemble.REG_X16) {
		if validKernelPointer(state.GetX(16)) {
			state.x16Candidate = state.GetX(16)
		}
	}
}

func (s *Scanner) invalidateUnsupportedDestinations(state *microState, inst *disassemble.Inst) {
	if inst == nil || operandCount(inst) == 0 {
		return
	}
	op := inst.Operands[0]
	switch op.Class {
	case disassemble.MEM_OFFSET, disassemble.MEM_PRE_IDX, disassemble.MEM_POST_IDX, disassemble.LABEL:
		return
	}
	for idx := 0; idx < int(op.NumRegisters); idx++ {
		reg := op.Registers[idx]
		if reg == disassemble.REG_SP {
			state.sp = 0
			continue
		}
		if idx, ok := registerToIndex(reg); ok {
			state.clearTracked(idx)
		}
	}
}

func (s *Scanner) stateWriteAddress(state *microState, idx int, value uint64) {
	if idx < 0 || idx >= len(state.regs) {
		return
	}
	state.setKnownBase(idx, value)
	if idx == 16 && validKernelPointer(value) {
		state.x16Candidate = value
	}
}

func (s *Scanner) applyMicroAdd(state *microState, inst *disassemble.Inst) {
	dstReg, dstOK := operandRegister(&inst.Operands[0], 0)
	srcReg, srcOK := operandRegister(&inst.Operands[1], 0)
	if operandCount(inst) < 3 || !dstOK || !srcOK {
		return
	}
	dstIdx, dstOK := registerToIndex(dstReg)
	srcIdx, srcOK := registerToIndex(srcReg)
	if !dstOK || !srcOK {
		return
	}
	imm := inst.Operands[2].GetImmediate()
	if dstReg == disassemble.REG_SP && srcReg == disassemble.REG_SP {
		state.sp += imm
		return
	}
	srcBase := state.regBase[srcIdx]
	srcLoadAddr := state.regLoadAddr[srcIdx]
	srcValue := state.regs[srcIdx]
	srcKnown := state.regKnown[srcIdx]
	state.clearTracked(dstIdx)
	if is32BitReg(dstReg) {
		if srcKnown {
			if value, ok := addSignedOffset(srcValue, int64(imm)); ok {
				state.setKnownValue(dstIdx, normalizeRegWrite(dstReg, value))
			}
		}
		return
	}
	if srcBase != 0 {
		if value, ok := addSignedOffset(srcBase, int64(imm)); ok {
			s.stateWriteAddress(state, dstIdx, value)
			return
		}
	}
	if srcLoadAddr != 0 {
		if addr, ok := addSignedOffset(srcLoadAddr, int64(imm)); ok {
			state.regLoadAddr[dstIdx] = addr
			return
		}
	}
	if srcKnown {
		if value, ok := addSignedOffset(srcValue, int64(imm)); ok {
			state.setKnownValue(dstIdx, normalizeRegWrite(dstReg, value))
			if dstIdx == 16 && validKernelPointer(value) {
				state.x16Candidate = value
			}
		}
	}
}

func (s *Scanner) applyMicroSub(state *microState, inst *disassemble.Inst) {
	dstReg, dstRegOK := operandRegister(&inst.Operands[0], 0)
	srcReg, srcRegOK := operandRegister(&inst.Operands[1], 0)
	if operandCount(inst) < 3 || !dstRegOK || !srcRegOK {
		return
	}
	imm := inst.Operands[2].GetImmediate()
	if dstReg == disassemble.REG_SP && srcReg == disassemble.REG_SP {
		state.sp -= imm
		return
	}
	dstIdx, dstOK := registerToIndex(dstReg)
	srcIdx, srcOK := registerToIndex(srcReg)
	if !dstOK || !srcOK {
		return
	}
	state.clearTracked(dstIdx)
	if srcValue := state.regs[srcIdx]; state.regKnown[srcIdx] && srcValue >= imm {
		state.setKnownValue(dstIdx, normalizeRegWrite(dstReg, srcValue-imm))
	}
}

func (s *Scanner) applyMicroMov(state *microState, inst *disassemble.Inst) {
	dstReg, dstRegOK := operandRegister(&inst.Operands[0], 0)
	if operandCount(inst) < 2 || !dstRegOK {
		return
	}
	dstIdx, dstOK := registerToIndex(dstReg)
	if !dstOK {
		return
	}
	state.clearTracked(dstIdx)
	if srcReg, ok := operandRegister(&inst.Operands[1], 0); ok {
		srcIdx, srcOK := registerToIndex(srcReg)
		if srcOK {
			if is32BitReg(dstReg) {
				if state.regKnown[srcIdx] {
					state.setKnownValue(dstIdx, normalizeRegWrite(dstReg, state.regs[srcIdx]))
				}
			} else {
				state.copyTracked(dstIdx, srcIdx)
			}
			if dstIdx == 16 && validKernelPointer(state.regs[dstIdx]) {
				state.x16Candidate = state.regs[dstIdx]
			}
		}
		return
	}
	state.setKnownValue(dstIdx, normalizeRegWrite(dstReg, inst.Operands[1].GetImmediate()))
}

func (s *Scanner) applyMicroMovWide(state *microState, inst *disassemble.Inst, invert bool, keep bool) {
	dstReg, dstRegOK := operandRegister(&inst.Operands[0], 0)
	if operandCount(inst) < 2 || !dstRegOK {
		return
	}
	dstIdx, dstOK := registerToIndex(dstReg)
	if !dstOK {
		return
	}
	imm := inst.Operands[1].GetImmediate()
	prevKnown := state.regKnown[dstIdx]
	value := imm
	if invert {
		value = ^imm
	}
	if keep {
		if !prevKnown {
			state.clearTracked(dstIdx)
			return
		}
		shift := uint32(0)
		if inst.Operands[1].ShiftValueUsed {
			shift = inst.Operands[1].ShiftValue
		}
		mask := uint64(0xffff) << shift
		value = (state.regs[dstIdx] & ^mask) | (imm & mask)
	}
	state.setKnownValue(dstIdx, normalizeRegWrite(dstReg, value))
	if dstIdx == 16 && validKernelPointer(value) {
		state.x16Candidate = value
	}
}

func (s *Scanner) applyMicroOrr(state *microState, inst *disassemble.Inst) {
	dstReg, dstRegOK := operandRegister(&inst.Operands[0], 0)
	if operandCount(inst) < 3 || !dstRegOK {
		return
	}
	dstIdx, dstOK := registerToIndex(dstReg)
	if !dstOK {
		return
	}
	state.clearTracked(dstIdx)
	switch {
	case operandRegisterCount(&inst.Operands[1]) > 0 && operandRegisterCount(&inst.Operands[2]) > 0:
		reg1, _ := operandRegister(&inst.Operands[1], 0)
		reg2, _ := operandRegister(&inst.Operands[2], 0)
		if reg1 == disassemble.REG_XZR || reg1 == disassemble.REG_WZR {
			srcIdx, ok := registerToIndex(reg2)
			if ok {
				if is32BitReg(dstReg) {
					if state.regKnown[srcIdx] {
						state.setKnownValue(dstIdx, normalizeRegWrite(dstReg, state.regs[srcIdx]))
					}
				} else {
					state.copyTracked(dstIdx, srcIdx)
				}
			}
		} else if reg2 == disassemble.REG_XZR || reg2 == disassemble.REG_WZR {
			srcIdx, ok := registerToIndex(reg1)
			if ok {
				if is32BitReg(dstReg) {
					if state.regKnown[srcIdx] {
						state.setKnownValue(dstIdx, normalizeRegWrite(dstReg, state.regs[srcIdx]))
					}
				} else {
					state.copyTracked(dstIdx, srcIdx)
				}
			}
		}
	}
	if dstIdx == 16 && validKernelPointer(state.regs[dstIdx]) {
		state.x16Candidate = state.regs[dstIdx]
	}
}

func (s *Scanner) applyMicroLoad(state *microState, inst *disassemble.Inst, pair bool) {
	if !pair {
		dstReg, ok := operandRegister(&inst.Operands[0], 0)
		if operandCount(inst) < 2 || !ok {
			return
		}
		dstIdx, ok := registerToIndex(dstReg)
		if !ok {
			return
		}
		access, ok := s.trackedLoadAddress(state, &inst.Operands[1])
		if !ok {
			state.clearTracked(dstIdx)
			return
		}
		state.clearTracked(dstIdx)
		if access.writeBack && !access.writeBackAfter {
			state.applyMemWriteBack(access)
		}
		state.regLoadAddr[dstIdx] = access.addr
		value, known := s.loadValueAt(state.owner, state, access.addr)
		state.regs[dstIdx] = normalizeRegWrite(dstReg, value)
		state.regKnown[dstIdx] = known
		if is32BitReg(dstReg) || !known {
			state.regLoadAddr[dstIdx] = 0
		}
		if access.writeBack && access.writeBackAfter {
			state.applyMemWriteBack(access)
		}
		if dstIdx == 16 && validKernelPointer(value) {
			state.x16Candidate = value
		}
		return
	}

	if operandCount(inst) < 3 {
		return
	}
	access, ok := s.trackedLoadAddress(state, &inst.Operands[2])
	if !ok {
		return
	}
	if access.writeBack && !access.writeBackAfter {
		state.applyMemWriteBack(access)
	}
	for i := range 2 {
		dstReg, ok := operandRegister(&inst.Operands[i], 0)
		if !ok {
			continue
		}
		dstIdx, ok := registerToIndex(dstReg)
		if !ok {
			continue
		}
		state.clearTracked(dstIdx)
		addr := access.addr + uint64(i*8)
		state.regLoadAddr[dstIdx] = addr
		value, known := s.loadValueAt(state.owner, state, addr)
		state.regs[dstIdx] = normalizeRegWrite(dstReg, value)
		state.regKnown[dstIdx] = known
		if is32BitReg(dstReg) || !known {
			state.regLoadAddr[dstIdx] = 0
		}
		if dstIdx == 16 && validKernelPointer(value) {
			state.x16Candidate = value
		}
	}
	if access.writeBack && access.writeBackAfter {
		state.applyMemWriteBack(access)
	}
}

func (s *Scanner) applyMicroStore(state *microState, inst *disassemble.Inst, pair bool) {
	if !pair {
		srcReg, ok := operandRegister(&inst.Operands[0], 0)
		if operandCount(inst) < 2 || !ok {
			return
		}
		access, ok := state.memoryAccess(&inst.Operands[1])
		if !ok {
			return
		}
		if access.writeBack && !access.writeBackAfter {
			state.applyMemWriteBack(access)
		}
		if access.baseIsSP {
			srcIdx, ok := registerToIndex(srcReg)
			if ok {
				state.writeStack(access.addr, state.regs[srcIdx])
			}
		}
		if access.writeBack && access.writeBackAfter {
			state.applyMemWriteBack(access)
		}
		return
	}

	if operandCount(inst) < 3 {
		return
	}
	access, ok := state.memoryAccess(&inst.Operands[2])
	if !ok {
		return
	}
	if access.writeBack && !access.writeBackAfter {
		state.applyMemWriteBack(access)
	}
	if access.baseIsSP {
		for i := range 2 {
			srcReg, ok := operandRegister(&inst.Operands[i], 0)
			if !ok {
				continue
			}
			srcIdx, ok := registerToIndex(srcReg)
			if !ok {
				continue
			}
			state.writeStack(access.addr+uint64(i*8), state.regs[srcIdx])
		}
	}
	if access.writeBack && access.writeBackAfter {
		state.applyMemWriteBack(access)
	}
}
