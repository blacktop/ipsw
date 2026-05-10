package iokit

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/go-macho"
)

const (
	dispatchSizeClassic = uint64(24)
	dispatchSize2022    = uint64(40)
	maxSelectorCount    = 4096
)

type methodAnalysis struct {
	kind       string
	addr       uint64
	owner      *macho.File
	arrayBase  uint64
	arrayBases []uint64
	stride     uint64
	count      int
	note       string
}

type methodCacheKey struct {
	addr     uint64
	kindHint string
}

type linearExpr struct {
	valid bool
	base  uint64
	coeff uint64
	alts  []uint64
	note  string
}

type decodedInst struct {
	disassemble.Inst
}

func (a *analyzer) analyzeExternalMethod(addr uint64, kindHint string) methodAnalysis {
	if addr == 0 {
		return methodAnalysis{kind: DispatchUnknown, note: "vtable_unresolved"}
	}
	key := methodCacheKey{addr: addr, kindHint: kindHint}
	if cached, ok := a.methods[key]; ok {
		return cached
	}
	out := a.analyzeExternalMethodUncached(addr, kindHint)
	a.methods[key] = out
	return out
}

func (a *analyzer) analyzeExternalMethodUncached(addr uint64, kindHint string) methodAnalysis {
	body, err := a.scanner.FunctionBodyAt(addr)
	if err != nil {
		return methodAnalysis{kind: DispatchUnknown, addr: addr, note: "vtable_unresolved"}
	}
	instrs := decodeInstructions(body.Data, body.Function.StartAddr, a.maxInst)
	var regs [31]linearExpr
	regs[0] = linearExpr{valid: true}
	regs[1] = linearExpr{valid: true, coeff: 1}

	selectorBound := -1
	pendingCompare := -1
	sawSelectorBranch := false
	best := methodAnalysis{kind: DispatchUnknown, addr: addr, owner: body.Owner, note: "indirect"}

	for idx := range instrs {
		inst := &instrs[idx].Inst
		if pendingCompare >= 0 {
			if count, ok := selectorCountFromBranch(inst, pendingCompare); ok {
				selectorBound = count
				sawSelectorBranch = true
			}
			pendingCompare = -1
		}
		if count, ok := selectorCompareCount(inst, regs); ok {
			pendingCompare = count
			if selectorBound < 0 {
				selectorBound = count
			}
		}
		if isCallOrTail(inst) {
			hint := a.callDispatchKindHint(inst)
			if hint == "" {
				hint = kindHint
			}
			if analysis, ok := a.dispatchAnalysisFromExpr(addr, body.Owner, regs[3], regs[4], selectorBound, hint); ok {
				best = analysis
			}
		}
		applyMethodInstruction(a, body.Owner, inst, regs[:])
		if isSelectorBranch(inst) {
			sawSelectorBranch = true
		}
	}
	if best.kind != DispatchUnknown {
		return best
	}
	if sawSelectorBranch && selectorBound > 0 && selectorBound <= maxSelectorCount {
		return methodAnalysis{
			kind:  DispatchSwitch,
			addr:  addr,
			owner: body.Owner,
			count: selectorBound,
			note:  "switch",
		}
	}
	return best
}

func (a *analyzer) dispatchAnalysisFromExpr(addr uint64, owner *macho.File, dispatchExpr, countExpr linearExpr, count int, kindHint string) (methodAnalysis, bool) {
	if count <= 0 && countExpr.valid && countExpr.coeff == 0 && countExpr.base > 0 && countExpr.base <= maxSelectorCount {
		count = int(countExpr.base)
	}
	if dispatchExpr.valid && dispatchExpr.coeff == 0 && dispatchExpr.base != 0 && count > 0 && count <= maxSelectorCount {
		bases := exprBases(dispatchExpr)
		stride, kind, ok := a.inferDispatchStride(owner, bases, count, kindHint)
		if !ok {
			return methodAnalysis{}, false
		}
		note := ""
		if len(bases) > 1 {
			note = "conditional_array"
		}
		return methodAnalysis{
			kind:       kind,
			addr:       addr,
			owner:      owner,
			arrayBase:  bases[0],
			arrayBases: bases,
			stride:     stride,
			count:      count,
			note:       note,
		}, true
	}
	expr := dispatchExpr
	if !expr.valid || expr.base == 0 {
		return methodAnalysis{}, false
	}
	var kind string
	switch expr.coeff {
	case dispatchSizeClassic:
		kind = DispatchExternalMethod
	case dispatchSize2022:
		kind = DispatchExternalMethod2022
	default:
		return methodAnalysis{}, false
	}
	analysis := methodAnalysis{
		kind:       kind,
		addr:       addr,
		owner:      owner,
		arrayBase:  expr.base,
		arrayBases: []uint64{expr.base},
		stride:     expr.coeff,
		count:      count,
	}
	if count <= 0 || count > maxSelectorCount {
		analysis.note = "bounds_unknown"
	}
	return analysis, true
}

func (a *analyzer) inferDispatchStride(owner *macho.File, bases []uint64, count int, kindHint string) (uint64, string, bool) {
	classicScore := a.dispatchStrideScore(owner, bases, count, dispatchSizeClassic)
	dispatch2022Score := a.dispatchStrideScore(owner, bases, count, dispatchSize2022)
	if dispatch2022Score > classicScore {
		return dispatchSize2022, DispatchExternalMethod2022, dispatch2022Score > 0
	}
	if dispatch2022Score == classicScore && dispatch2022Score > 0 {
		if stride, kind, ok := tiedDispatchStride(kindHint, a.hasDispatch2022Evidence(owner, bases, count)); ok {
			return stride, kind, true
		}
	}
	return dispatchSizeClassic, DispatchExternalMethod, classicScore > 0
}

func (a *analyzer) dispatchStrideScore(owner *macho.File, bases []uint64, count int, stride uint64) int {
	score := 0
	limit := min(count, 8)
	for _, base := range bases {
		for selector := range limit {
			addr := base + uint64(selector)*stride
			fn, ok := a.scanner.ReadPointerAt(owner, addr)
			if !ok || fn == 0 {
				continue
			}
			score += 2
			if _, err := a.scanner.ReadUint32At(owner, addr+8); err == nil {
				score++
			}
			if _, err := a.scanner.ReadUint32At(owner, addr+16); err == nil {
				score++
			}
		}
	}
	return score
}

func tiedDispatchStride(kindHint string, hasEvidence2022 bool) (uint64, string, bool) {
	if kindHint == DispatchExternalMethod2022 || hasEvidence2022 {
		return dispatchSize2022, DispatchExternalMethod2022, true
	}
	if kindHint == DispatchExternalMethod {
		return dispatchSizeClassic, DispatchExternalMethod, true
	}
	return 0, "", false
}

func (a *analyzer) hasDispatch2022Evidence(owner *macho.File, bases []uint64, count int) bool {
	limit := min(count, 8)
	for _, base := range bases {
		for selector := range limit {
			addr := base + uint64(selector)*dispatchSize2022
			fn, ok := a.scanner.ReadPointerAt(owner, addr)
			if !ok || fn == 0 {
				continue
			}
			flags, err := a.scanner.ReadUint32At(owner, addr+24)
			if err == nil && flags > 0 && flags <= 0xff {
				return true
			}
			entitlement, ok := a.scanner.ReadPointerAt(owner, addr+32)
			if !ok {
				if raw, err := a.scanner.ReadUint64At(owner, addr+32); err == nil {
					entitlement = raw
				}
			}
			if entitlement != 0 {
				if str, err := a.scanner.ReadCStringAt(owner, entitlement); err == nil && validLiteralString(str) {
					return true
				}
			}
		}
	}
	return false
}

func dispatchKindHintForFamily(family string) string {
	switch family {
	case "IOUserClient2022":
		return DispatchExternalMethod2022
	case "IOUserClient":
		return DispatchExternalMethod
	default:
		return ""
	}
}

func (a *analyzer) callDispatchKindHint(inst *disassemble.Inst) string {
	target, ok := labelTarget(inst)
	if !ok {
		return ""
	}
	name := a.symbolName(target)
	switch {
	case strings.Contains(name, "IOUserClient2022::externalMethod"):
		return DispatchExternalMethod2022
	case strings.Contains(name, "IOUserClient::externalMethod"):
		return DispatchExternalMethod
	default:
		return ""
	}
}

func decodeInstructions(data []byte, start uint64, maxInst int) []decodedInst {
	var decoder disassemble.Decoder
	out := make([]decodedInst, 0, len(data)/4)
	r := bytes.NewReader(data)
	addr := start
	for len(out) < maxInst {
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

func applyMethodInstruction(a *analyzer, owner *macho.File, inst *disassemble.Inst, regs []linearExpr) {
	if applyConditionalSelect(inst, regs) {
		return
	}
	switch inst.Operation {
	case disassemble.ARM64_ADR, disassemble.ARM64_ADRP:
		if rd, ok := destRegIndex(inst); ok {
			if imm, ok := operandImm(inst, 1); ok {
				regs[rd] = linearExpr{valid: true, base: imm}
			}
		}
	case disassemble.ARM64_ADD:
		applyAdd(inst, regs)
	case disassemble.ARM64_LDR, disassemble.ARM64_LDUR:
		applyLoad(a, owner, inst, regs)
	case disassemble.ARM64_MOV:
		applyMove(inst, regs)
	case disassemble.ARM64_MOVZ:
		if rd, ok := destRegIndex(inst); ok {
			if imm, ok := operandImm(inst, 1); ok {
				regs[rd] = linearExpr{valid: true, base: imm}
			}
		}
	case disassemble.ARM64_MOVK:
		applyMoveKeep(inst, regs)
	case disassemble.ARM64_ORR:
		if !applyORRMove(inst, regs) {
			clearDest(inst, regs, "indirect")
		}
	default:
		if shouldClearDest(inst) {
			clearDest(inst, regs, "indirect")
		}
	}
	if isCall(inst.Operation) {
		clearVolatile(regs)
	}
}

func applyAdd(inst *disassemble.Inst, regs []linearExpr) {
	rd, ok := destRegIndex(inst)
	if !ok {
		return
	}
	leftIdx, ok := operandRegIndex(inst, 1)
	if !ok {
		clearReg(regs, rd, "indirect")
		return
	}
	left := regs[leftIdx]
	if imm, ok := operandImm(inst, 2); ok && operandIsImmediate(inst, 2) {
		if !left.valid {
			clearReg(regs, rd, left.note)
			return
		}
		regs[rd] = addImmediateExpr(left, imm)
		return
	}
	rightIdx, ok := operandRegIndex(inst, 2)
	if !ok {
		clearReg(regs, rd, "indirect")
		return
	}
	right := shiftedExpr(regs[rightIdx], &inst.Operands[2])
	regs[rd] = combineExpr(left, right)
}

func applyLoad(a *analyzer, owner *macho.File, inst *disassemble.Inst, regs []linearExpr) {
	rd, ok := destRegIndex(inst)
	if !ok {
		return
	}
	if target, ok := labelTarget(inst); ok {
		if ptr, ok := a.scanner.ReadPointerAt(owner, target); ok {
			regs[rd] = linearExpr{valid: true, base: ptr}
			return
		}
		regs[rd] = linearExpr{valid: true, base: target}
		return
	}
	baseIdx, ok := operandRegIndex(inst, 1)
	if !ok {
		clearReg(regs, rd, "indirect")
		return
	}
	base := regs[baseIdx]
	if !base.valid || base.coeff != 0 {
		clearReg(regs, rd, base.note)
		return
	}
	off, _ := operandImm(inst, 1)
	addr := base.base + off
	if ptr, ok := a.scanner.ReadPointerAt(owner, addr); ok {
		regs[rd] = linearExpr{valid: true, base: ptr}
		return
	}
	clearReg(regs, rd, "indirect")
}

func applyMove(inst *disassemble.Inst, regs []linearExpr) {
	rd, ok := destRegIndex(inst)
	if !ok {
		return
	}
	if rn, ok := operandRegIndex(inst, 1); ok {
		regs[rd] = regs[rn]
		return
	}
	if imm, ok := operandImm(inst, 1); ok {
		regs[rd] = linearExpr{valid: true, base: imm}
		return
	}
	clearReg(regs, rd, "indirect")
}

func applyMoveKeep(inst *disassemble.Inst, regs []linearExpr) {
	rd, ok := destRegIndex(inst)
	if !ok {
		return
	}
	imm, ok := operandImm(inst, 1)
	if !ok || !regs[rd].valid || regs[rd].coeff != 0 {
		clearReg(regs, rd, "indirect")
		return
	}
	shift := uint64(0)
	if inst.NumOps > 1 && inst.Operands[1].ShiftValueUsed {
		shift = uint64(inst.Operands[1].ShiftValue)
	}
	mask := uint64(0xffff) << shift
	regs[rd].base = (regs[rd].base &^ mask) | ((imm << shift) & mask)
}

func applyORRMove(inst *disassemble.Inst, regs []linearExpr) bool {
	rd, ok := destRegIndex(inst)
	if !ok {
		return false
	}
	rn, rnOK := operandReg(inst, 1)
	rm, rmOK := operandReg(inst, 2)
	if rnOK && rmOK && isZeroReg(rn) {
		if idx, ok := regIndex(rm); ok {
			regs[rd] = regs[idx]
			return true
		}
	}
	return false
}

func applyConditionalSelect(inst *disassemble.Inst, regs []linearExpr) bool {
	if inst == nil || strings.ToLower(inst.Operation.String()) != "csel" {
		return false
	}
	rd, ok := destRegIndex(inst)
	if !ok {
		return true
	}
	leftIdx, leftOK := operandRegIndex(inst, 1)
	rightIdx, rightOK := operandRegIndex(inst, 2)
	if !leftOK || !rightOK {
		clearReg(regs, rd, "indirect")
		return true
	}
	left := regs[leftIdx]
	right := regs[rightIdx]
	if !left.valid || !right.valid || left.coeff != right.coeff {
		clearReg(regs, rd, "indirect")
		return true
	}
	if left.base == right.base && len(left.alts) == 0 && len(right.alts) == 0 {
		regs[rd] = left
		return true
	}
	alts := compactUint64s(append(exprBases(left), exprBases(right)...))
	if len(alts) == 0 {
		clearReg(regs, rd, "indirect")
		return true
	}
	regs[rd] = linearExpr{
		valid: true,
		base:  alts[0],
		coeff: left.coeff,
		alts:  alts,
	}
	return true
}

func addImmediateExpr(expr linearExpr, imm uint64) linearExpr {
	expr.base += imm
	if len(expr.alts) == 0 {
		return expr
	}
	alts := append([]uint64(nil), expr.alts...)
	for idx := range alts {
		alts[idx] += imm
	}
	alts = compactUint64s(alts)
	if len(alts) > 0 {
		expr.base = alts[0]
	}
	expr.alts = alts
	return expr
}

func combineExpr(left, right linearExpr) linearExpr {
	if !left.valid {
		return linearExpr{note: noteFor(left)}
	}
	if !right.valid {
		return linearExpr{note: noteFor(right)}
	}
	out := linearExpr{
		valid: true,
		base:  left.base + right.base,
		coeff: left.coeff + right.coeff,
	}
	bases := combinedBases(left, right)
	switch len(bases) {
	case 0:
	case 1:
		out.base = bases[0]
	default:
		out.base = bases[0]
		out.alts = bases
	}
	return out
}

func combinedBases(left, right linearExpr) []uint64 {
	leftBases := exprBases(left)
	rightBases := exprBases(right)
	if len(leftBases) == 1 && len(rightBases) == 1 {
		return []uint64{leftBases[0] + rightBases[0]}
	}
	out := make([]uint64, 0, len(leftBases)*len(rightBases))
	for _, leftBase := range leftBases {
		for _, rightBase := range rightBases {
			out = append(out, leftBase+rightBase)
		}
	}
	return compactUint64s(out)
}

func shiftedExpr(expr linearExpr, op *disassemble.Op) linearExpr {
	if !expr.valid || op == nil || !op.ShiftValueUsed {
		return expr
	}
	shift := uint64(op.ShiftValue)
	alts := append([]uint64(nil), expr.alts...)
	for idx := range alts {
		alts[idx] <<= shift
	}
	return linearExpr{
		valid: true,
		base:  expr.base << shift,
		coeff: expr.coeff << shift,
		alts:  alts,
	}
}

func exprBases(expr linearExpr) []uint64 {
	if len(expr.alts) > 0 {
		return compactUint64s(expr.alts)
	}
	return []uint64{expr.base}
}

func compactUint64s(items []uint64) []uint64 {
	if len(items) == 0 {
		return nil
	}
	out := append([]uint64(nil), items...)
	for idx := range out {
		for j := idx + 1; j < len(out); j++ {
			if out[j] < out[idx] {
				out[idx], out[j] = out[j], out[idx]
			}
		}
	}
	write := 0
	for _, item := range out {
		if item == 0 {
			continue
		}
		if write > 0 && out[write-1] == item {
			continue
		}
		out[write] = item
		write++
	}
	return out[:write]
}

func selectorCompareCount(inst *disassemble.Inst, regs [31]linearExpr) (int, bool) {
	if inst == nil || operandCount(inst) < 2 {
		return 0, false
	}
	opName := strings.ToLower(inst.Operation.String())
	if opName != "cmp" && opName != "subs" {
		return 0, false
	}
	reg, ok := operandReg(inst, 0)
	if !ok || !isSelectorReg(reg) {
		return 0, false
	}
	if imm, ok := operandImm(inst, 1); ok && imm <= maxSelectorCount {
		return int(imm), true
	}
	idx, ok := operandRegIndex(inst, 1)
	if !ok || idx >= len(regs) {
		return 0, false
	}
	val := regs[idx]
	if val.valid && val.coeff == 0 && val.base <= maxSelectorCount {
		return int(val.base), true
	}
	return 0, false
}

func selectorCountFromBranch(inst *disassemble.Inst, compare int) (int, bool) {
	if compare < 0 || inst == nil {
		return 0, false
	}
	opName := strings.ToLower(inst.Operation.String())
	switch {
	case strings.Contains(opName, ".hi"):
		return compare + 1, true
	case strings.Contains(opName, ".hs"), strings.Contains(opName, ".cs"),
		strings.Contains(opName, ".ge"):
		return compare, true
	default:
		return 0, false
	}
}

func isSelectorBranch(inst *disassemble.Inst) bool {
	if inst == nil {
		return false
	}
	opName := strings.ToLower(inst.Operation.String())
	return strings.HasPrefix(opName, "b.") || strings.HasPrefix(opName, "tbz") ||
		strings.HasPrefix(opName, "tbnz") || strings.HasPrefix(opName, "cbz") ||
		strings.HasPrefix(opName, "cbnz")
}

func isCallOrTail(inst *disassemble.Inst) bool {
	if inst == nil {
		return false
	}
	switch inst.Operation {
	case disassemble.ARM64_BL, disassemble.ARM64_B,
		disassemble.ARM64_BLR, disassemble.ARM64_BLRAA,
		disassemble.ARM64_BLRAAZ, disassemble.ARM64_BLRAB,
		disassemble.ARM64_BLRABZ, disassemble.ARM64_BR,
		disassemble.ARM64_BRAA, disassemble.ARM64_BRAAZ:
		return true
	default:
		return false
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

func shouldClearDest(inst *disassemble.Inst) bool {
	if inst == nil || inst.NumOps == 0 {
		return false
	}
	if _, ok := destRegIndex(inst); !ok {
		return false
	}
	op := strings.ToLower(inst.Operation.String())
	if strings.HasPrefix(op, "st") || strings.HasPrefix(op, "b.") ||
		op == "b" || op == "br" || op == "ret" || op == "cmp" {
		return false
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

func operandIsImmediate(inst *disassemble.Inst, idx int) bool {
	if inst == nil || int(inst.NumOps) <= idx {
		return false
	}
	switch inst.Operands[idx].Class {
	case disassemble.IMM32, disassemble.IMM64, disassemble.STR_IMM:
		return true
	default:
		return false
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

func isSelectorReg(reg disassemble.Register) bool {
	return reg == disassemble.REG_X1 || reg == disassemble.REG_W1
}

func isZeroReg(reg disassemble.Register) bool {
	return reg == disassemble.REG_XZR || reg == disassemble.REG_WZR
}

func operandCount(inst *disassemble.Inst) int {
	if inst == nil {
		return 0
	}
	return int(inst.NumOps)
}

func clearDest(inst *disassemble.Inst, regs []linearExpr, note string) {
	if rd, ok := destRegIndex(inst); ok {
		clearReg(regs, rd, note)
	}
}

func clearReg(regs []linearExpr, idx int, note string) {
	if idx >= 0 && idx < len(regs) {
		if note == "" {
			note = "indirect"
		}
		regs[idx] = linearExpr{note: note}
	}
}

func clearVolatile(regs []linearExpr) {
	for idx := 0; idx <= 17 && idx < len(regs); idx++ {
		regs[idx] = linearExpr{note: "indirect"}
	}
}

func noteFor(expr linearExpr) string {
	if expr.note != "" {
		return expr.note
	}
	return "indirect"
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
