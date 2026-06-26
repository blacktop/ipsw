package iokit

import (
	"bytes"
	"encoding/binary"
	"io"
	"maps"
	"strings"
	"unicode/utf8"

	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/go-macho"
)

const (
	dispatchSizeClassic = uint64(24)
	dispatchSize2022    = uint64(40)
	dispatchSizeLegacy  = uint64(48)
	maxSelectorCount    = 4096
)

type methodAnalysis struct {
	kind               string
	addr               uint64
	owner              *macho.File
	arrayBase          uint64
	arrayBases         []uint64
	selectedEntries    map[int]uint64
	stride             uint64
	count              int
	selectorLowerBound int
	note               string
	switchCases        map[int]switchCaseInfo
}

type switchCaseInfo struct {
	methodAddr              uint64
	readsStructureInput     bool
	readsStructureInputSize bool
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

type selectorWindow struct {
	count      int
	lowerBound int
}

type pendingBiasedSelectorCompare struct {
	compare    int
	lowerBound int
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
	biasedBound := selectorWindow{count: -1}
	pendingCompare := -1
	pendingBiased := pendingBiasedSelectorCompare{compare: -1}
	lastSelectorCompare := -1
	sawSelectorBranch := false
	var selectedDispatch [31]map[int]uint64
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
		if pendingBiased.compare >= 0 {
			if count, ok := selectorCountFromBranch(inst, pendingBiased.compare); ok {
				biasedBound = selectorWindow{count: count, lowerBound: pendingBiased.lowerBound}
			}
			pendingBiased = pendingBiasedSelectorCompare{compare: -1}
		}
		if count, ok := selectorCompareCount(inst, regs); ok {
			pendingCompare = count
			lastSelectorCompare = count
			if selectorBound < 0 {
				selectorBound = count
			}
		} else if pending, ok := biasedSelectorCompare(inst, regs); ok {
			pendingBiased = pending
			if biasedBound.count < 0 {
				// Before seeing the branch, assume the canonical (selector-k) > N
				// shape. The branch-specific path above tightens this for >= tests.
				biasedBound = selectorWindow{count: pending.compare + 1, lowerBound: pending.lowerBound}
			}
		}
		applySelectedDispatchInstruction(inst, regs[:], &selectedDispatch, lastSelectorCompare)
		if isCallOrTail(inst) {
			hint := a.callDispatchKindHint(inst)
			if hint == "" {
				hint = kindHint
			}
			if analysis, ok := a.dispatchAnalysisFromExpr(addr, body.Owner, regs[3], regs[4], dispatchSelectorBound(selectorBound, biasedBound), hint); ok {
				best = analysis
			} else if analysis, ok := selectedDispatchAnalysis(addr, body.Owner, selectedDispatch[3], hint); ok {
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
		switchInstrs := a.switchAnalysisInstructions(body.Data, body.Function.StartAddr, instrs)
		return methodAnalysis{
			kind:        DispatchSwitch,
			addr:        addr,
			owner:       body.Owner,
			count:       selectorBound,
			note:        "switch",
			switchCases: a.analyzeSwitchCaseBodies(body.Owner, switchInstrs, selectorBound),
		}
	}
	return best
}

func (a *analyzer) analyzeLegacyExternalMethod(addr uint64) methodAnalysis {
	if addr == 0 {
		return methodAnalysis{kind: DispatchUnknown, note: "vtable_unresolved"}
	}
	key := methodCacheKey{addr: addr, kindHint: "legacy"}
	if cached, ok := a.methods[key]; ok {
		return cached
	}
	out := a.analyzeLegacyExternalMethodUncached(addr)
	a.methods[key] = out
	return out
}

func (a *analyzer) analyzeLegacyExternalMethodUncached(addr uint64) methodAnalysis {
	body, err := a.scanner.FunctionBodyAt(addr)
	if err != nil {
		return methodAnalysis{kind: DispatchUnknown, addr: addr, note: "vtable_unresolved"}
	}
	instrs := decodeInstructions(body.Data, body.Function.StartAddr, a.maxInst)
	var regs [31]linearExpr
	regs[0] = linearExpr{valid: true}
	regs[2] = linearExpr{valid: true, coeff: 1}

	selectorBound := -1
	pendingCompare := -1
	for idx := range instrs {
		inst := &instrs[idx].Inst
		if pendingCompare >= 0 {
			if count, ok := selectorCountFromBranch(inst, pendingCompare); ok {
				selectorBound = count
			}
			pendingCompare = -1
		}
		if count, ok := legacyIndexCompareCount(inst, regs); ok {
			pendingCompare = count
			if selectorBound < 0 {
				selectorBound = count
			}
		}
		if isReturn(inst) {
			if analysis, ok := legacyDispatchAnalysisFromExpr(addr, body.Owner, regs[0], selectorBound); ok {
				return analysis
			}
		}
		applyMethodInstruction(a, body.Owner, inst, regs[:])
	}
	return methodAnalysis{kind: DispatchUnknown, addr: addr, owner: body.Owner, note: "indirect"}
}

func legacyDispatchAnalysisFromExpr(addr uint64, owner *macho.File, tableExpr linearExpr, count int) (methodAnalysis, bool) {
	if !tableExpr.valid || tableExpr.base == 0 || tableExpr.coeff != dispatchSizeLegacy {
		return methodAnalysis{}, false
	}
	analysis := methodAnalysis{
		kind:       DispatchExternalMethodLegacy,
		addr:       addr,
		owner:      owner,
		arrayBase:  tableExpr.base,
		arrayBases: []uint64{tableExpr.base},
		stride:     dispatchSizeLegacy,
		count:      count,
	}
	if count <= 0 || count > maxSelectorCount {
		analysis.note = "bounds_unknown"
	}
	return analysis, true
}

func selectedDispatchAnalysis(addr uint64, owner *macho.File, entries map[int]uint64, kindHint string) (methodAnalysis, bool) {
	if owner == nil || len(entries) == 0 {
		return methodAnalysis{}, false
	}
	kind := kindHint
	stride := dispatchSizeClassic
	if kind == DispatchExternalMethod2022 {
		stride = dispatchSize2022
	} else {
		kind = DispatchExternalMethod
	}
	return methodAnalysis{
		kind:            kind,
		addr:            addr,
		owner:           owner,
		selectedEntries: cloneSelectedDispatchEntries(entries),
		stride:          stride,
		count:           len(entries),
		note:            "selected_entry",
	}, true
}

func applySelectedDispatchInstruction(inst *disassemble.Inst, regs []linearExpr, selected *[31]map[int]uint64, selector int) {
	if inst == nil || selected == nil {
		return
	}
	rd, hasDest := destRegIndex(inst)
	if !hasDest || rd >= len(selected) {
		return
	}
	selected[rd] = nil
	if copied, ok := selectedDispatchMove(inst, selected); ok {
		selected[rd] = copied
		return
	}
	selectedSelector, entry, ok := conditionalSelectedDispatchEntry(inst, regs, selector)
	if !ok {
		return
	}
	selected[rd] = map[int]uint64{selectedSelector: entry}
}

func selectedDispatchMove(inst *disassemble.Inst, selected *[31]map[int]uint64) (map[int]uint64, bool) {
	if inst == nil || inst.Operation != disassemble.ARM64_MOV || selected == nil {
		return nil, false
	}
	rn, ok := operandRegIndex(inst, 1)
	if !ok || rn >= len(selected) || len(selected[rn]) == 0 {
		return nil, false
	}
	return cloneSelectedDispatchEntries(selected[rn]), true
}

func conditionalSelectedDispatchEntry(inst *disassemble.Inst, regs []linearExpr, selector int) (int, uint64, bool) {
	if selector < 0 || inst == nil || strings.ToLower(inst.Operation.String()) != "csel" {
		return 0, 0, false
	}
	rd, ok := destRegIndex(inst)
	if !ok || rd != 3 {
		return 0, 0, false
	}
	leftIdx, leftOK := operandRegIndex(inst, 1)
	rightIdx, rightOK := operandRegIndex(inst, 2)
	if !leftOK || !rightOK || leftIdx >= len(regs) || rightIdx >= len(regs) {
		return 0, 0, false
	}
	left := regs[leftIdx]
	right := regs[rightIdx]
	if !isEqualCondition(inst) {
		return 0, 0, false
	}
	if isSingleDispatchEntryExpr(left) && !right.valid {
		return selector, left.base, true
	}
	return 0, 0, false
}

func isSingleDispatchEntryExpr(expr linearExpr) bool {
	return expr.valid && expr.base != 0 && expr.coeff == 0 && len(expr.alts) == 0
}

func isEqualCondition(inst *disassemble.Inst) bool {
	if inst == nil {
		return false
	}
	for idx := 0; idx < int(inst.NumOps); idx++ {
		if strings.EqualFold(inst.Operands[idx].Condition.String(inst.Operands[idx].Class), "EQ") {
			return true
		}
	}
	return false
}

func cloneSelectedDispatchEntries(entries map[int]uint64) map[int]uint64 {
	if len(entries) == 0 {
		return nil
	}
	out := make(map[int]uint64, len(entries))
	maps.Copy(out, entries)
	return out
}

func (a *analyzer) dispatchAnalysisFromExpr(addr uint64, owner *macho.File, dispatchExpr, countExpr linearExpr, bounds selectorWindow, kindHint string) (methodAnalysis, bool) {
	count := bounds.count
	if count <= 0 && countExpr.valid && countExpr.coeff == 0 && countExpr.base > 0 && countExpr.base <= maxSelectorCount {
		if !a.registerCountCorroborated(owner, dispatchExpr, int(countExpr.base), kindHint) {
			return methodAnalysis{}, false
		}
		count = int(countExpr.base)
		bounds = selectorWindow{count: count}
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
			kind:               kind,
			addr:               addr,
			owner:              owner,
			arrayBase:          bases[0],
			arrayBases:         bases,
			stride:             stride,
			count:              count,
			selectorLowerBound: bounds.lowerBound,
			note:               note,
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
	bases, ok := normalizedDispatchBases(expr, bounds.lowerBound)
	if !ok {
		return methodAnalysis{}, false
	}
	analysis := methodAnalysis{
		kind:               kind,
		addr:               addr,
		owner:              owner,
		arrayBase:          bases[0],
		arrayBases:         bases,
		stride:             expr.coeff,
		count:              count,
		selectorLowerBound: bounds.lowerBound,
	}
	if len(bases) > 1 {
		analysis.note = "conditional_array"
	}
	if count <= 0 || count > maxSelectorCount {
		analysis.note = "bounds_unknown"
	}
	return analysis, true
}

// registerCountCorroborated guards the register-derived dispatch count.
// The dispatchCount lives in X4 only for the IOUserClient2022
// dispatchExternalMethod(selector, args, dispatch, count, target, ref)
// form, where the count is also CMP'd against the selector (the
// selectorBound path). When no such comparison bound exists, an X4 value
// is just as likely to be a leaked constant from the single-method
// externalMethod form (for example the low bits of a kIOReturn* error
// immediate). The count is accepted only when the last spanned dispatch
// entry of EVERY candidate base resolves to a real function body.
// dispatchRecords later emits count selectors for every base in
// arrayBases, so for a conditional-array dispatch a single bogus/shorter
// alternate base would otherwise be over-read into adjacent data;
// requiring all bases to corroborate fails the whole table closed instead.
func (a *analyzer) registerCountCorroborated(owner *macho.File, dispatchExpr linearExpr, count int, kindHint string) bool {
	if count <= 0 {
		return false
	}
	bases := exprBases(dispatchExpr)
	if len(bases) == 0 {
		return false
	}
	for _, base := range bases {
		if !a.lastDispatchEntryResolves(owner, base, count, kindHint) {
			return false
		}
	}
	return true
}

func (a *analyzer) lastDispatchEntryResolves(owner *macho.File, base uint64, count int, kindHint string) bool {
	strides := []uint64{dispatchSizeClassic, dispatchSize2022}
	switch kindHint {
	case DispatchExternalMethod2022:
		strides = []uint64{dispatchSize2022}
	case DispatchExternalMethod:
		strides = []uint64{dispatchSizeClassic}
	}
	for _, stride := range strides {
		addr := base + uint64(count-1)*stride
		fn, ok := a.scanner.ReadPointerAt(owner, addr)
		if !ok || fn == 0 {
			continue
		}
		if _, err := a.scanner.FunctionBodyAt(fn); err == nil {
			return true
		}
	}
	return false
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

func (a *analyzer) switchAnalysisInstructions(data []byte, start uint64, instrs []decodedInst) []decodedInst {
	if a == nil || a.maxSwitchInst <= a.maxInst || len(instrs) < a.maxInst {
		return instrs
	}
	return decodeInstructions(data, start, a.maxSwitchInst)
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
	case disassemble.ARM64_SUB:
		applySub(inst, regs)
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
	case disassemble.ARM64_SMULL, disassemble.ARM64_UMULL:
		applyMultiply(inst, regs)
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

// applySub models only the `SUB rD, rN, #imm` immediate form, which the
// compiler emits to bias a selector before bounding it (the canonical
// (selector - k) > N idiom in IOUserClient::externalMethod dispatchers that
// reserve selector 0). The biased value is tracked as a linear expression so
// biasedSelectorCompare can recover the true selector bound. Register-
// operand SUBs clear the destination (they are not part of this idiom).
func applySub(inst *disassemble.Inst, regs []linearExpr) {
	rd, ok := destRegIndex(inst)
	if !ok {
		return
	}
	leftIdx, ok := operandRegIndex(inst, 1)
	if !ok {
		clearReg(regs, rd, "indirect")
		return
	}
	imm, ok := operandImm(inst, 2)
	if !ok || !operandIsImmediate(inst, 2) {
		clearReg(regs, rd, "indirect")
		return
	}
	left := regs[leftIdx]
	if !left.valid {
		clearReg(regs, rd, left.note)
		return
	}
	regs[rd] = addImmediateExpr(left, 0-imm)
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
	if !ok || !regs[rd].valid {
		clearReg(regs, rd, "indirect")
		return
	}
	shift := uint64(0)
	if inst.NumOps > 1 && inst.Operands[1].ShiftValueUsed {
		shift = uint64(inst.Operands[1].ShiftValue)
	}
	if regs[rd].coeff != 0 {
		if shift >= 48 {
			return
		}
		clearReg(regs, rd, "indirect")
		return
	}
	mask := uint64(0xffff) << shift
	regs[rd].base = (regs[rd].base &^ mask) | ((imm << shift) & mask)
}

func applyMultiply(inst *disassemble.Inst, regs []linearExpr) {
	rd, ok := destRegIndex(inst)
	if !ok {
		return
	}
	leftIdx, leftOK := operandRegIndex(inst, 1)
	rightIdx, rightOK := operandRegIndex(inst, 2)
	if !leftOK || !rightOK {
		clearReg(regs, rd, "indirect")
		return
	}
	if scaled, ok := scaleExprByConstant(regs[leftIdx], regs[rightIdx]); ok {
		regs[rd] = scaled
		return
	}
	if scaled, ok := scaleExprByConstant(regs[rightIdx], regs[leftIdx]); ok {
		regs[rd] = scaled
		return
	}
	clearReg(regs, rd, "indirect")
}

func scaleExprByConstant(expr linearExpr, scalar linearExpr) (linearExpr, bool) {
	if !expr.valid || !scalar.valid || scalar.coeff != 0 || len(scalar.alts) != 0 {
		return linearExpr{}, false
	}
	out, ok := scaleExpr(expr, scalar.base)
	return out, ok
}

func scaleExpr(expr linearExpr, scalar uint64) (linearExpr, bool) {
	if !expr.valid {
		return linearExpr{}, false
	}
	if scalar == 0 {
		return linearExpr{valid: true}, true
	}
	base, ok := checkedMul(expr.base, scalar)
	if !ok {
		return linearExpr{}, false
	}
	coeff, ok := checkedMul(expr.coeff, scalar)
	if !ok {
		return linearExpr{}, false
	}
	out := linearExpr{valid: true, base: base, coeff: coeff, note: expr.note}
	if len(expr.alts) == 0 {
		return out, true
	}
	out.alts = make([]uint64, 0, len(expr.alts))
	for _, alt := range expr.alts {
		scaled, ok := checkedMul(alt, scalar)
		if !ok {
			return linearExpr{}, false
		}
		out.alts = append(out.alts, scaled)
	}
	out.alts = compactUint64s(out.alts)
	if len(out.alts) > 0 {
		out.base = out.alts[0]
	}
	return out, true
}

func checkedMul(left, right uint64) (uint64, bool) {
	if left != 0 && right > ^uint64(0)/left {
		return 0, false
	}
	return left * right, true
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

func normalizedDispatchBases(expr linearExpr, selectorLowerBound int) ([]uint64, bool) {
	bases := exprBases(expr)
	if selectorLowerBound <= 0 || expr.coeff == 0 {
		return bases, true
	}
	adjust, ok := checkedMul(uint64(selectorLowerBound), expr.coeff)
	if !ok {
		return nil, false
	}
	out := make([]uint64, 0, len(bases))
	for _, base := range bases {
		if base > ^uint64(0)-adjust {
			return nil, false
		}
		out = append(out, base+adjust)
	}
	return compactUint64s(out), true
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
	return compareCountForIndexReg(inst, regs, isSelectorReg)
}

func legacyIndexCompareCount(inst *disassemble.Inst, regs [31]linearExpr) (int, bool) {
	return compareCountForIndexReg(inst, regs, isLegacyIndexReg)
}

func compareCountForIndexReg(inst *disassemble.Inst, regs [31]linearExpr, isIndexReg func(disassemble.Register) bool) (int, bool) {
	if inst == nil || operandCount(inst) < 2 {
		return 0, false
	}
	opName := strings.ToLower(inst.Operation.String())
	if opName != "cmp" && opName != "subs" {
		return 0, false
	}
	reg, ok := operandReg(inst, 0)
	if !ok || !isIndexReg(reg) {
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

// biasedSelectorCompare recovers a selector bound from the
// `SUB rTmp, selector, #k; CMP rTmp, #N` idiom, where the compared register
// holds the selector biased by a nonzero constant (coeff == 1, base == -k). It
// returns the compared biased-index limit plus the external selector lower bound
// k. This is intentionally separate from selectorCompareCount: the bound it
// produces feeds only the static dispatch-table path, never the switch fallback,
// so switch dispatchers that happen to bias their selector keep their existing
// classification.
func biasedSelectorCompare(inst *disassemble.Inst, regs [31]linearExpr) (pendingBiasedSelectorCompare, bool) {
	if inst == nil || operandCount(inst) < 2 {
		return pendingBiasedSelectorCompare{}, false
	}
	opName := strings.ToLower(inst.Operation.String())
	if opName != "cmp" && opName != "subs" {
		return pendingBiasedSelectorCompare{}, false
	}
	reg, ok := operandReg(inst, 0)
	if !ok || isSelectorReg(reg) {
		return pendingBiasedSelectorCompare{}, false
	}
	idx, ok := regIndex(reg)
	if !ok || idx >= len(regs) {
		return pendingBiasedSelectorCompare{}, false
	}
	val := regs[idx]
	if !val.valid || val.coeff != 1 || val.base == 0 || len(val.alts) != 0 {
		return pendingBiasedSelectorCompare{}, false
	}
	imm, ok := operandImm(inst, 1)
	if !ok {
		return pendingBiasedSelectorCompare{}, false
	}
	lowerBound := 0 - val.base
	if lowerBound == 0 || lowerBound > maxSelectorCount || imm > maxSelectorCount {
		return pendingBiasedSelectorCompare{}, false
	}
	return pendingBiasedSelectorCompare{compare: int(imm), lowerBound: int(lowerBound)}, true
}

// dispatchSelectorBound picks the selector window handed to the dispatch-table
// path. The direct X1/W1 compare wins when present; the biased-selector window
// (from the SUB-then-compare idiom) is the fallback so a static dispatch table
// can still be sized without treating selector 0 as table[-1].
func dispatchSelectorBound(selectorBound int, biasedBound selectorWindow) selectorWindow {
	if selectorBound > 0 {
		return selectorWindow{count: selectorBound}
	}
	return biasedBound
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

func isReturn(inst *disassemble.Inst) bool {
	return inst != nil && inst.Operation == disassemble.ARM64_RET
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

func isLegacyIndexReg(reg disassemble.Register) bool {
	return reg == disassemble.REG_X2 || reg == disassemble.REG_W2
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

const (
	ioExternalMethodArgumentsStructureInputOffset     = uint64(0x30)
	ioExternalMethodArgumentsStructureInputSizeOffset = uint64(0x38)
	maxSwitchCaseScanInstructions                     = 96
)

func (a *analyzer) analyzeSwitchCaseBodies(owner *macho.File, instrs []decodedInst, selectorCount int) map[int]switchCaseInfo {
	targets := switchCaseTargets(instrs)
	if len(targets) == 0 {
		targets = a.switchJumpTableTargets(owner, instrs, selectorCount)
	}
	if len(targets) == 0 {
		return nil
	}
	indexByAddr := make(map[uint64]int, len(instrs))
	for idx := range instrs {
		indexByAddr[instrs[idx].Address] = idx
	}
	dispatchIdx := len(instrs)
	for _, target := range targets {
		if idx, ok := indexByAddr[target]; ok && idx < dispatchIdx {
			dispatchIdx = idx
		}
	}
	prologueArgs := argumentRegistersBefore(instrs, dispatchIdx)
	out := make(map[int]switchCaseInfo)
	for selector, target := range targets {
		idx, ok := indexByAddr[target]
		if !ok {
			continue
		}
		info := a.scanSwitchCaseBody(instrs, idx, prologueArgs, true)
		if info.methodAddr != 0 || info.readsStructureInput || info.readsStructureInputSize {
			out[selector] = info
		}
	}
	return out
}

func switchCaseTargets(instrs []decodedInst) map[int]uint64 {
	out := make(map[int]uint64)
	var regs [31]linearExpr
	regs[1] = linearExpr{valid: true, coeff: 1}
	pendingSelector := -1
	for idx := range instrs {
		inst := &instrs[idx].Inst
		if pendingSelector >= 0 {
			if target, ok := equalBranchTarget(inst); ok {
				out[pendingSelector] = target
			}
			pendingSelector = -1
		}
		if selector, ok := selectorCompareCount(inst, regs); ok {
			pendingSelector = selector
		}
		applySwitchIndexInstruction(inst, &regs)
	}
	return out
}

func (a *analyzer) switchJumpTableTargets(owner *macho.File, instrs []decodedInst, selectorCount int) map[int]uint64 {
	if a == nil || owner == nil || selectorCount <= 0 || selectorCount > maxSelectorCount {
		return nil
	}
	var regs [31]linearExpr
	regs[1] = linearExpr{valid: true, coeff: 1}
	jumpTableLoads := make(map[int]uint64)
	jumpTableTargets := make(map[int]uint64)

	for idx := range instrs {
		inst := &instrs[idx].Inst
		if rd, ok := destRegIndex(inst); ok {
			delete(jumpTableLoads, rd)
			delete(jumpTableTargets, rd)
		}
		if offsetReg, tableBase, ok := switchJumpTableLoad(inst, regs); ok {
			jumpTableLoads[offsetReg] = tableBase
		}
		if targetReg, tableBase, ok := switchJumpTableAdd(inst, regs, jumpTableLoads); ok {
			jumpTableTargets[targetReg] = tableBase
		}
		if targetReg, ok := branchRegisterIndex(inst); ok {
			if tableBase, ok := jumpTableTargets[targetReg]; ok {
				return a.switchJumpTableTargetsFromTable(owner, tableBase, selectorCount)
			}
		}
		applySwitchIndexInstruction(inst, &regs)
	}
	return nil
}

func switchJumpTableLoad(inst *disassemble.Inst, regs [31]linearExpr) (int, uint64, bool) {
	if inst == nil || inst.Operation != disassemble.ARM64_LDRSW {
		return 0, 0, false
	}
	offsetReg, ok := destRegIndex(inst)
	if !ok {
		return 0, 0, false
	}
	baseReg, indexReg, ok := memoryBaseAndIndexRegIndex(inst, 1)
	if !ok || !isSwitchSelectorExpr(regs[indexReg]) {
		return 0, 0, false
	}
	base := regs[baseReg]
	if !base.valid || base.coeff != 0 || base.base == 0 {
		return 0, 0, false
	}
	return offsetReg, base.base, true
}

func switchJumpTableAdd(inst *disassemble.Inst, regs [31]linearExpr, jumpTableLoads map[int]uint64) (int, uint64, bool) {
	if inst == nil || inst.Operation != disassemble.ARM64_ADD {
		return 0, 0, false
	}
	targetReg, ok := destRegIndex(inst)
	if !ok {
		return 0, 0, false
	}
	leftReg, leftOK := operandRegIndex(inst, 1)
	rightReg, rightOK := operandRegIndex(inst, 2)
	if !leftOK || !rightOK {
		return 0, 0, false
	}
	if tableBase, ok := switchJumpTableAddBase(regs, jumpTableLoads, leftReg, rightReg); ok {
		return targetReg, tableBase, true
	}
	if tableBase, ok := switchJumpTableAddBase(regs, jumpTableLoads, rightReg, leftReg); ok {
		return targetReg, tableBase, true
	}
	return 0, 0, false
}

func switchJumpTableAddBase(regs [31]linearExpr, jumpTableLoads map[int]uint64, baseReg, offsetReg int) (uint64, bool) {
	tableBase, ok := jumpTableLoads[offsetReg]
	if !ok {
		return 0, false
	}
	base := regs[baseReg]
	if !base.valid || base.coeff != 0 || base.base != tableBase {
		return 0, false
	}
	return tableBase, true
}

func (a *analyzer) switchJumpTableTargetsFromTable(owner *macho.File, tableBase uint64, selectorCount int) map[int]uint64 {
	out := make(map[int]uint64)
	for selector := range selectorCount {
		raw, err := a.scanner.ReadUint32At(owner, tableBase+uint64(selector)*4)
		if err != nil {
			continue
		}
		target, ok := switchJumpTargetAddress(tableBase, int32(raw))
		if ok {
			out[selector] = target
		}
	}
	return out
}

func switchJumpTargetAddress(base uint64, offset int32) (uint64, bool) {
	if offset >= 0 {
		target := base + uint64(offset)
		return target, target >= base
	}
	magnitude := uint64(-int64(offset))
	if magnitude > base {
		return 0, false
	}
	return base - magnitude, true
}

func isSwitchSelectorExpr(expr linearExpr) bool {
	return expr.valid && expr.base == 0 && expr.coeff == 1 && len(expr.alts) == 0
}

func memoryBaseAndIndexRegIndex(inst *disassemble.Inst, operandIdx int) (int, int, bool) {
	if inst == nil || int(inst.NumOps) <= operandIdx {
		return 0, 0, false
	}
	op := &inst.Operands[operandIdx]
	if op.NumRegisters < 2 {
		return 0, 0, false
	}
	base, baseOK := regIndex(op.Registers[0])
	index, indexOK := regIndex(op.Registers[1])
	return base, index, baseOK && indexOK
}

func branchRegisterIndex(inst *disassemble.Inst) (int, bool) {
	if inst == nil {
		return 0, false
	}
	switch inst.Operation {
	case disassemble.ARM64_BR, disassemble.ARM64_BRAA, disassemble.ARM64_BRAAZ,
		disassemble.ARM64_BRAB, disassemble.ARM64_BRABZ:
		return operandRegIndex(inst, 0)
	default:
		return 0, false
	}
}

func equalBranchTarget(inst *disassemble.Inst) (uint64, bool) {
	if inst == nil {
		return 0, false
	}
	opName := strings.ToLower(inst.Operation.String())
	if !strings.Contains(opName, ".eq") {
		return 0, false
	}
	return labelTarget(inst)
}

func (a *analyzer) scanSwitchCaseBody(instrs []decodedInst, targetIdx int, argRegs [31]bool, scanCallee bool) switchCaseInfo {
	info := switchCaseInfo{}
	limit := min(len(instrs), targetIdx+maxSwitchCaseScanInstructions)
	for idx := targetIdx; idx < limit; idx++ {
		inst := &instrs[idx].Inst
		if off, ok := argumentFieldRead(inst, argRegs); ok {
			switch off {
			case ioExternalMethodArgumentsStructureInputOffset:
				info.readsStructureInput = true
			case ioExternalMethodArgumentsStructureInputSizeOffset:
				info.readsStructureInputSize = true
			}
		}
		if scanCallee && inst.Operation == disassemble.ARM64_BL {
			if target, ok := labelTarget(inst); ok {
				if info.methodAddr == 0 {
					info.methodAddr = target
				}
				calleeInfo := a.analyzeSwitchCaseCallee(target, argRegs)
				info.readsStructureInput = info.readsStructureInput || calleeInfo.readsStructureInput
				info.readsStructureInputSize = info.readsStructureInputSize || calleeInfo.readsStructureInputSize
			}
		}
		applyArgumentRegisterInstruction(inst, &argRegs)
		if idx > targetIdx && isCaseTerminator(inst) {
			break
		}
	}
	return info
}

func (a *analyzer) analyzeSwitchCaseCallee(addr uint64, argRegs [31]bool) switchCaseInfo {
	if a == nil || addr == 0 {
		return switchCaseInfo{}
	}
	body, err := a.scanner.FunctionBodyAt(addr)
	if err != nil {
		return switchCaseInfo{}
	}
	instrs := decodeInstructions(body.Data, body.Function.StartAddr, a.maxInst)
	targetIdx := 0
	for idx := range instrs {
		if instrs[idx].Address == addr {
			targetIdx = idx
			break
		}
	}
	return a.scanSwitchCaseBody(instrs, targetIdx, argRegs, false)
}

func argumentRegistersBefore(instrs []decodedInst, targetIdx int) [31]bool {
	var argRegs [31]bool
	argRegs[2] = true
	for idx := 0; idx < min(targetIdx, len(instrs)); idx++ {
		applyArgumentRegisterInstruction(&instrs[idx].Inst, &argRegs)
	}
	return argRegs
}

func argumentFieldRead(inst *disassemble.Inst, argRegs [31]bool) (uint64, bool) {
	if inst == nil {
		return 0, false
	}
	switch inst.Operation {
	case disassemble.ARM64_LDR, disassemble.ARM64_LDUR:
	default:
		return 0, false
	}
	baseIdx, ok := operandRegIndex(inst, 1)
	if !ok || baseIdx >= len(argRegs) || !argRegs[baseIdx] {
		return 0, false
	}
	off, ok := operandImm(inst, 1)
	if !ok {
		return 0, false
	}
	return off, true
}

func applyArgumentRegisterInstruction(inst *disassemble.Inst, argRegs *[31]bool) {
	if inst == nil {
		return
	}
	rd, hasDest := destRegIndex(inst)
	if !hasDest || rd >= len(argRegs) {
		if isCall(inst.Operation) {
			clearVolatileArgRegs(argRegs)
		}
		return
	}
	keep := false
	switch inst.Operation {
	case disassemble.ARM64_MOV:
		if rn, ok := operandRegIndex(inst, 1); ok && rn < len(argRegs) && argRegs[rn] {
			keep = true
		}
	case disassemble.ARM64_ADD:
		if rn, ok := operandRegIndex(inst, 1); ok && rn < len(argRegs) && argRegs[rn] {
			if _, ok := operandImm(inst, 2); ok && operandIsImmediate(inst, 2) {
				keep = true
			}
		}
	case disassemble.ARM64_ORR:
		if rn, rnOK := operandRegIndex(inst, 1); rnOK && rn < len(argRegs) && argRegs[rn] {
			if rm, rmOK := operandReg(inst, 2); rmOK && isZeroReg(rm) {
				keep = true
			}
		}
		if rm, rmOK := operandRegIndex(inst, 2); rmOK && rm < len(argRegs) && argRegs[rm] {
			if rn, rnOK := operandReg(inst, 1); rnOK && isZeroReg(rn) {
				keep = true
			}
		}
	}
	argRegs[rd] = keep
	if isCall(inst.Operation) {
		clearVolatileArgRegs(argRegs)
	}
}

func applySwitchIndexInstruction(inst *disassemble.Inst, regs *[31]linearExpr) {
	if inst == nil {
		return
	}
	switch inst.Operation {
	case disassemble.ARM64_ADR, disassemble.ARM64_ADRP:
		if rd, ok := destRegIndex(inst); ok {
			if imm, ok := operandImm(inst, 1); ok {
				regs[rd] = linearExpr{valid: true, base: imm}
			}
		}
	case disassemble.ARM64_MOV:
		applyMove(inst, regs[:])
	case disassemble.ARM64_ADD:
		applyAdd(inst, regs[:])
	case disassemble.ARM64_ORR:
		if !applyORRMove(inst, regs[:]) {
			clearDest(inst, regs[:], "indirect")
		}
	default:
		if shouldClearDest(inst) {
			clearDest(inst, regs[:], "indirect")
		}
	}
}

func clearVolatileArgRegs(argRegs *[31]bool) {
	for idx := 0; idx <= 17; idx++ {
		argRegs[idx] = false
	}
}

func isCaseTerminator(inst *disassemble.Inst) bool {
	if inst == nil {
		return false
	}
	if isReturn(inst) {
		return true
	}
	switch inst.Operation {
	case disassemble.ARM64_B, disassemble.ARM64_BR, disassemble.ARM64_BRAA, disassemble.ARM64_BRAAZ,
		disassemble.ARM64_BRAB, disassemble.ARM64_BRABZ:
		return true
	default:
		return false
	}
}
