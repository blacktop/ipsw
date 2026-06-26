package iokit

import (
	"strings"

	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/go-macho"
)

// IOAVFamily user clients inherit IOAVUserClient::externalMethod, a shared
// command-gated dispatcher that reads the per-class IOExternalMethodDispatch
// table and selector count from instance fields (this+0xE0/this+0xE8). Those
// fields are written at runtime by the class' own start(), which loads a static
// table via adrp/add and a literal count via mov before tail-calling
// IOAVUserClient::start. The externalMethod body never references the table, so
// the count/base are recoverable only by walking the start() chain.
//
// The constants below are the symbols and field offsets that key this resolver
// tightly to IOAVFamily; nothing else in the kernelcache uses this exact shape.
const (
	ioavExternalMethodSymbol = "IOAVUserClient::externalMethod"
	ioavStartRegistrarSymbol = "IOAVUserClient::start"
	// ioavStartChainDepth bounds the per-class tail-call walk
	// (subclass::start -> base::start -> IOAVUserClient::start is depth 3).
	ioavStartChainDepth = 4
)

// resolveIOAVDispatch recovers the IOExternalMethodDispatch table for an
// IOAVFamily user client whose externalMethod resolves to
// IOAVUserClient::externalMethod. It locates the class' own start(), walks the
// tail-call chain to the frame that registers the table with
// IOAVUserClient::start, and recovers the static table base (x2) and selector
// count (x3). It returns ok=false (leaving the caller's fail-closed placeholder
// in place) whenever the chain, the literals, or the corroboration check do not
// hold.
func (a *analyzer) resolveIOAVDispatch(info *classInfo) (methodAnalysis, bool) {
	startAddr, ok := a.namedVtableMethod(info, "start")
	if !ok {
		return methodAnalysis{}, false
	}
	base, count, owner, ok := a.walkIOAVStartChain(startAddr, ioavStartChainDepth)
	if !ok {
		return methodAnalysis{}, false
	}
	analysis := methodAnalysis{
		kind:       DispatchExternalMethod,
		addr:       startAddr,
		owner:      owner,
		arrayBase:  base,
		arrayBases: []uint64{base},
		stride:     dispatchSizeClassic,
		count:      count,
	}
	if !a.registerCountCorroborated(owner, linearExpr{valid: true, base: base}, count, DispatchExternalMethod) {
		return methodAnalysis{}, false
	}
	return analysis, true
}

// namedVtableMethod returns the address of the class' own override of method,
// matched by symbol in the class vtable (for example "<Class>::start(").
func (a *analyzer) namedVtableMethod(info *classInfo, method string) (uint64, bool) {
	for _, entry := range a.scanner.VtableEntries(info.Class, a.maxSlots) {
		if entry.Address == 0 {
			continue
		}
		if isNamedMethod(a.symbolName(entry.Address), method) {
			return entry.Address, true
		}
	}
	return 0, false
}

// walkIOAVStartChain follows the tail-call chain starting at addr until it finds
// the frame that tail-calls IOAVUserClient::start, returning the table base (x2)
// and selector count (x3) recovered from that frame. Each frame is analyzed with
// a fresh register file: the registrar receives the table/count from the frame
// that directly tail-calls it, so only that frame's linear-expr state matters.
func (a *analyzer) walkIOAVStartChain(addr uint64, depth int) (uint64, int, *macho.File, bool) {
	if depth <= 0 || addr == 0 {
		return 0, 0, nil, false
	}
	body, err := a.scanner.FunctionBodyAt(addr)
	if err != nil {
		return 0, 0, nil, false
	}
	instrs := decodeInstructions(body.Data, body.Function.StartAddr, a.maxInst)
	var regs [31]linearExpr
	for idx := range instrs {
		inst := &instrs[idx].Inst
		if isCallOrTail(inst) {
			target, ok := labelTarget(inst)
			if !ok {
				applyMethodInstruction(a, body.Owner, inst, regs[:])
				continue
			}
			name := a.symbolName(target)
			if strings.Contains(name, ioavStartRegistrarSymbol) {
				base, count, ok := ioavTableAndCount(regs)
				return base, count, body.Owner, ok
			}
			if isIOAVStartTailCall(inst, name) {
				return a.walkIOAVStartChain(target, depth-1)
			}
		}
		applyMethodInstruction(a, body.Owner, inst, regs[:])
	}
	return 0, 0, nil, false
}

// isIOAVStartTailCall reports whether inst is a tail branch into another
// class' start() (the subclass->base wrapper chain), as opposed to a regular
// call. Only unconditional B/BR-family branches continue the chain.
func isIOAVStartTailCall(inst *disassemble.Inst, name string) bool {
	if inst == nil {
		return false
	}
	switch inst.Operation {
	case disassemble.ARM64_B, disassemble.ARM64_BR,
		disassemble.ARM64_BRAA, disassemble.ARM64_BRAAZ,
		disassemble.ARM64_BRAB, disassemble.ARM64_BRABZ:
	default:
		return false
	}
	return isNamedMethod(name, "start")
}

// ioavTableAndCount extracts the table base (x2) and selector count (x3) from
// the register file at the IOAVUserClient::start tail-call. The table must be a
// resolved adrp/add address (coeff 0, nonzero base) and the count a literal in
// the valid selector range.
func ioavTableAndCount(regs [31]linearExpr) (uint64, int, bool) {
	table := regs[2]
	count := regs[3]
	if !table.valid || table.coeff != 0 || table.base == 0 || len(table.alts) != 0 {
		return 0, 0, false
	}
	if !count.valid || count.coeff != 0 || count.base == 0 ||
		count.base > maxSelectorCount || len(count.alts) != 0 {
		return 0, 0, false
	}
	return table.base, int(count.base), true
}
