package pacx

// This file adds the call-site side of the PAC cross-reference index. For each
// authenticated virtual call it recovers the (slot-offset, 16-bit hash) pair
// that the join in a later phase matches against the vtable-side (offset, pac)
// index built in index.go.
//
// The recovery is a faithful port of PacXplorer's MovkAnalyzer.analyze_movk. The
// discriminator of an address-diversified virtual call is blend(slot_address,
// hash): the modifier register passed to BLRAA/BLRAB holds the vtable slot
// address, and a MOVK #hash,LSL#48 blends the constant hash into its top bits.
// Both the hash AND the slot offset therefore live on the MODIFIER register's
// definition chain, not the target register's:
//
//	autda x9, x3               ; authenticate the vtable pointer (depac anchor)
//	add   x17, x9, #0x18       ; slot address = vtable + 0x18
//	ldr   x8, [x17]            ; load the function pointer (target reg, ignored)
//	movk  x17, #hash, lsl #48  ; blend the discriminator into the slot address
//	blraa x8, x17              ; authenticated indirect call
//
// Recovery walks backward from the call over the modifier register: it finds the
// MOVK #hash,LSL#48 that set it (the hash), then accumulates the slot offset from
// ADD immediates and pre-index LDR/LDRAA writeback displacements while following
// MOV/ORR renames, stopping at the depac anchor -- an LDRAA with pre-index
// writeback, or AUTD* data-key auth on the tracked register -- that proves a
// genuine authenticated vtable dispatch. An edge is emitted only when that
// anchor is reached (seen_depac). A discriminator built from a pure constant with
// no register source is a static/devirtualized dispatch and is rejected, as is
// any non-fallthrough control-flow barrier, call that may clobber the tracked
// volatile register, unrecognized clobber of the tracked register, and the
// zero-modifier BLRAAZ/BLRABZ forms. Missed edges (recall) are acceptable; wrong
// edges are not.

import (
	"sort"

	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/ipsw/pkg/xref"
)

// DefaultCallSiteWindow bounds how many instructions the backward register walk
// inspects from a call site. It only limits recall: the walk always stops at the
// first depac anchor, control-flow barrier, call clobber, or clobber of the
// tracked register, so a wider window can never produce a wrong edge.
const DefaultCallSiteWindow = 64

// CallSite is one authenticated virtual call recovered from a function body.
type CallSite struct {
	// Addr is the address of the BLRAA/BLRAB instruction.
	Addr uint64
	// CallerFuncAddr is the start address of the enclosing function.
	CallerFuncAddr uint64
	// KeyB reports whether the call uses the B instruction key (BLRAB). False is
	// the A instruction key (BLRAA).
	KeyB bool
}

// CallKey identifies an authenticated virtual call by the vtable slot byte
// offset and the 16-bit discriminator hash recovered at the call site. It is the
// same shape as the forward index key (offset, pac), so the two join directly.
type CallKey struct {
	Offset uint64
	Hash   uint16
}

// CallSiteIndex maps each (offset, hash) key to every call site dispatching
// through it.
type CallSiteIndex map[CallKey][]CallSite

// FuncBody is a single function's machine code to scan for authenticated
// virtual calls.
type FuncBody struct {
	Addr uint64
	Code []byte
}

// BuildCallSiteIndex scans each function body for register-form BLRAA/BLRAB
// calls and returns the (offset, hash) -> call-site index. A window <= 0 uses
// DefaultCallSiteWindow. Per-key call sites are sorted for deterministic output.
func BuildCallSiteIndex(funcs []FuncBody, window int) CallSiteIndex {
	if window <= 0 {
		window = DefaultCallSiteWindow
	}
	idx := make(CallSiteIndex)
	for _, fb := range funcs {
		idx.scan(xref.Decode(fb.Code, fb.Addr), fb.Addr, window)
	}
	idx.sortSites()
	return idx
}

// Sites returns the call sites recorded for a (offset, hash) key, or nil.
func (idx CallSiteIndex) Sites(offset uint64, hash uint16) []CallSite {
	return idx[CallKey{Offset: offset, Hash: hash}]
}

func (idx CallSiteIndex) sortSites() {
	for k := range idx {
		sites := idx[k]
		sort.Slice(sites, func(i, j int) bool {
			if sites[i].Addr != sites[j].Addr {
				return sites[i].Addr < sites[j].Addr
			}
			return sites[i].CallerFuncAddr < sites[j].CallerFuncAddr
		})
	}
}

func (idx CallSiteIndex) scan(instrs []xref.Instruction, funcAddr uint64, window int) {
	for i := range instrs {
		call, ok := xref.DecodeAuthCallReg(&instrs[i].Inst)
		if !ok {
			continue // skips BLRAAZ/BLRABZ and non-auth BLR
		}
		offset, hash, ok := recoverKey(instrs, i, call.ModifierReg, window)
		if !ok {
			continue
		}
		key := CallKey{Offset: offset, Hash: hash}
		idx[key] = append(idx[key], CallSite{Addr: instrs[i].Address, CallerFuncAddr: funcAddr, KeyB: call.KeyB})
	}
}

// recoverKey backtraces the modifier (discriminator) register from a call site
// to recover the (slot offset, 16-bit hash) pair. It first locates the
// MOVK #hash,LSL#48 that set the modifier, then accumulates the slot offset along
// the register's definition chain until it reaches the depac anchor that proves
// an authenticated vtable dispatch. It returns false if the modifier is not set
// by a MOVK, if no anchor is reached, or if the chain hits a static-dispatch
// constant or an unrecognized clobber.
func recoverKey(instrs []xref.Instruction, callIdx int, modReg disassemble.Register, window int) (uint64, uint16, bool) {
	ctx := modReg
	var hash uint16
	haveMovk := false
	var offset int64
	start := max(callIdx-window, 0)
	for idx := callIdx - 1; idx >= start; idx-- {
		inst := &instrs[idx].Inst
		if isNonFallthroughTerminator(inst.Operation) {
			return 0, 0, false
		}
		if isCallClobber(inst.Operation, ctx) {
			return 0, 0, false
		}
		if !haveMovk {
			// Locate the MOVK #hash,LSL#48 that set the modifier register; the
			// modifier must not be redefined by anything else before it.
			if d, imm, ok := xref.DecodeMovkShift48(inst); ok && sameReg(d, ctx) {
				hash, haveMovk = imm, true
				continue
			}
			if writesReg(inst, ctx) {
				return 0, 0, false
			}
			continue
		}
		st := classifyStep(inst, ctx)
		switch st.kind {
		case stepAnchorLdraa:
			return normalizeOffset(offset+st.off, hash)
		case stepAnchorAuth:
			return normalizeOffset(offset, hash)
		case stepRename:
			ctx = st.src
		case stepAddImm:
			ctx = st.src
			offset += st.off
		case stepLdrWriteback:
			offset += st.off
		case stepNone:
		default: // stepStatic, stepClobber
			return 0, 0, false
		}
	}
	return 0, 0, false
}

func normalizeOffset(off int64, hash uint16) (uint64, uint16, bool) {
	if off < 0 || off%8 != 0 {
		return 0, 0, false
	}
	return uint64(off), hash, true
}

// stepKind classifies how an instruction affects the tracked slot-address
// register during the backward modifier-chain walk.
type stepKind uint8

const (
	stepNone         stepKind = iota // does not affect the tracked register
	stepAnchorLdraa                  // LDRAA/LDRAB [ctx,#off]!: add off, depac, stop
	stepAnchorAuth                   // AUTD* data-key auth dest==ctx: depac, stop
	stepRename                       // ctx <- srcReg (MOV/ORR register move)
	stepAddImm                       // ctx <- srcReg + imm
	stepLdrWriteback                 // LDR/LDUR [ctx,#off]!: add off, keep ctx
	stepStatic                       // ctx set from a pure constant (static dispatch)
	stepClobber                      // ctx redefined by an unrecognized instruction
)

type regStep struct {
	kind stepKind
	src  disassemble.Register
	off  int64
}

// classifyStep reports how inst redefines or advances the tracked slot-address
// register ctx during the modifier-chain walk. It recognizes the two vtable
// pointer depac anchors (authenticated-load writeback and in-place data-key
// authenticate), the offset accumulators (ADD immediate, pre-index load
// writeback), register renames, and falls back to a conservative clobber check
// so any unrecognized definition of ctx halts the walk without emitting an edge.
func classifyStep(inst *disassemble.Inst, ctx disassemble.Register) regStep {
	if xref.IsLdrAuth(inst.Operation) {
		return classifyLdrAuthStep(inst, ctx)
	}
	if xref.IsAuthPtr(inst.Operation) {
		if ap, ok := xref.DecodeAuthPtr(inst); ok && ap.Data && sameReg(ap.DestReg, ctx) {
			return regStep{kind: stepAnchorAuth}
		}
		return regStep{kind: stepNone}
	}
	if lw, ok := xref.DecodeLoadPreIndex(inst); ok {
		if sameReg(lw.BaseReg, ctx) {
			return regStep{kind: stepLdrWriteback, off: lw.Offset}
		}
		if sameReg(lw.DestReg, ctx) {
			return regStep{kind: stepClobber}
		}
		return regStep{kind: stepNone}
	}
	switch inst.Operation {
	case disassemble.ARM64_MOV:
		return classifyMovStep(inst, ctx)
	case disassemble.ARM64_ORR:
		return classifyOrrStep(inst, ctx)
	case disassemble.ARM64_ADD:
		return classifyAddStep(inst, ctx)
	case disassemble.ARM64_MOVZ, disassemble.ARM64_MOVN,
		disassemble.ARM64_ADR, disassemble.ARM64_ADRP:
		if dst, ok := xref.OperandReg(inst, 0); ok && sameReg(dst, ctx) {
			return regStep{kind: stepStatic}
		}
		return regStep{kind: stepNone}
	case disassemble.ARM64_MOVK, disassemble.ARM64_LDR, disassemble.ARM64_LDUR:
		if dst, ok := xref.OperandReg(inst, 0); ok && sameReg(dst, ctx) {
			return regStep{kind: stepClobber}
		}
		return regStep{kind: stepNone}
	}
	if writesReg(inst, ctx) {
		return regStep{kind: stepClobber}
	}
	return regStep{kind: stepNone}
}

func classifyLdrAuthStep(inst *disassemble.Inst, ctx disassemble.Register) regStep {
	la, ok := xref.DecodeLdrAuth(inst)
	if !ok {
		return regStep{kind: stepNone}
	}
	if la.Writeback && sameReg(la.BaseReg, ctx) {
		return regStep{kind: stepAnchorLdraa, off: la.Offset}
	}
	if sameReg(la.DestReg, ctx) {
		return regStep{kind: stepClobber}
	}
	return regStep{kind: stepNone}
}

func classifyMovStep(inst *disassemble.Inst, ctx disassemble.Register) regStep {
	dst, ok := xref.OperandReg(inst, 0)
	if !ok || !sameReg(dst, ctx) {
		return regStep{kind: stepNone}
	}
	if isWReg(dst) {
		return regStep{kind: stepClobber}
	}
	if src, ok := xref.OperandReg(inst, 1); ok {
		if isZeroReg(src) {
			return regStep{kind: stepStatic}
		}
		if isWReg(src) {
			return regStep{kind: stepClobber}
		}
		return regStep{kind: stepRename, src: src}
	}
	if _, ok := xref.OperandImm(inst, 1); ok {
		return regStep{kind: stepStatic}
	}
	return regStep{kind: stepClobber}
}

func classifyOrrStep(inst *disassemble.Inst, ctx disassemble.Register) regStep {
	dst, ok := xref.OperandReg(inst, 0)
	if !ok || !sameReg(dst, ctx) {
		return regStep{kind: stepNone}
	}
	rn, rnOK := xref.OperandReg(inst, 1)
	rm, rmOK := xref.OperandReg(inst, 2)
	if isWReg(dst) {
		return regStep{kind: stepClobber}
	}
	if rnOK && rmOK && isZeroReg(rn) && !isZeroReg(rm) && !isWReg(rm) && isIdentityRegOperand(inst, 2) {
		return regStep{kind: stepRename, src: rm}
	}
	return regStep{kind: stepClobber}
}

func classifyAddStep(inst *disassemble.Inst, ctx disassemble.Register) regStep {
	dst, ok := xref.OperandReg(inst, 0)
	if !ok || !sameReg(dst, ctx) {
		return regStep{kind: stepNone}
	}
	src, ok := xref.OperandReg(inst, 1)
	if !ok {
		return regStep{kind: stepClobber}
	}
	if isWReg(dst) || isWReg(src) {
		return regStep{kind: stepClobber}
	}
	// ADD Xd,Xn,#imm accumulates the immediate and follows Xn. An ADD with a
	// register third operand carries the offset in a register we do not track;
	// reject rather than emit a wrong offset.
	if imm, ok := xref.OperandImm(inst, 2); ok {
		return regStep{kind: stepAddImm, src: src, off: int64(imm)}
	}
	return regStep{kind: stepClobber}
}

// writesReg conservatively reports whether inst clobbers reg: as an operand-0
// destination, any pre/post-index base writeback, or the second destination of a
// load-pair. It intentionally over-reports (e.g. a store's operand 0) so the
// backward walk halts on any potential clobber rather than skipping past it.
func writesReg(inst *disassemble.Inst, reg disassemble.Register) bool {
	if dst, ok := xref.OperandReg(inst, 0); ok && sameReg(dst, reg) {
		return true
	}
	for idx := range int(inst.NumOps) {
		if base, ok := xref.OperandReg(inst, idx); ok && sameReg(base, reg) {
			if _, _, wb, ok := xref.MemoryAccess(inst, idx); ok && wb {
				return true
			}
		}
	}
	switch inst.Operation {
	case disassemble.ARM64_LDP, disassemble.ARM64_LDNP, disassemble.ARM64_LDPSW:
		if d2, ok := xref.OperandReg(inst, 1); ok && sameReg(d2, reg) {
			return true
		}
	}
	return false
}

func isNonFallthroughTerminator(op disassemble.Operation) bool {
	switch op {
	case disassemble.ARM64_B,
		disassemble.ARM64_BR,
		disassemble.ARM64_BRAA,
		disassemble.ARM64_BRAAZ,
		disassemble.ARM64_BRAB,
		disassemble.ARM64_BRABZ,
		disassemble.ARM64_RET,
		disassemble.ARM64_RETAA,
		disassemble.ARM64_RETAASPPC,
		disassemble.ARM64_RETAASPPCR,
		disassemble.ARM64_RETAB,
		disassemble.ARM64_RETABSPPC,
		disassemble.ARM64_RETABSPPCR,
		disassemble.ARM64_ERET,
		disassemble.ARM64_ERETAA,
		disassemble.ARM64_ERETAB:
		return true
	default:
		return false
	}
}

func isCallClobber(op disassemble.Operation, reg disassemble.Register) bool {
	return isCall(op) && isVolatileReg(reg)
}

func isCall(op disassemble.Operation) bool {
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

func isVolatileReg(r disassemble.Register) bool {
	r = canonReg(r)
	return r >= disassemble.REG_X0 && r <= disassemble.REG_X17
}

func isZeroReg(r disassemble.Register) bool {
	return r == disassemble.REG_XZR || r == disassemble.REG_WZR
}

func isWReg(r disassemble.Register) bool {
	return (r >= disassemble.REG_W0 && r <= disassemble.REG_W30) ||
		r == disassemble.REG_WZR ||
		r == disassemble.REG_WSP
}

func isIdentityRegOperand(inst *disassemble.Inst, idx int) bool {
	if inst == nil || idx < 0 || idx >= int(inst.NumOps) {
		return false
	}
	op := inst.Operands[idx]
	if !op.ShiftValueUsed {
		return true
	}
	return op.ShiftType == disassemble.SHIFT_TYPE_LSL && op.ShiftValue == 0
}

// sameReg reports whether a and b denote the same architectural register,
// treating a 32-bit W view as its 64-bit X register. A W write zero-extends and
// therefore redefines the full X register, so the modifier-chain walk must treat
// a write to wN as a definition/clobber of a tracked xN (and vice versa).
func sameReg(a, b disassemble.Register) bool {
	return canonReg(a) == canonReg(b)
}

// canonReg maps a 32-bit W register to its 64-bit X counterpart (and WZR/WSP to
// XZR/SP); every other register is returned unchanged.
func canonReg(r disassemble.Register) disassemble.Register {
	switch {
	case r >= disassemble.REG_W0 && r <= disassemble.REG_W30:
		return r + (disassemble.REG_X0 - disassemble.REG_W0)
	case r == disassemble.REG_WZR:
		return disassemble.REG_XZR
	case r == disassemble.REG_WSP:
		return disassemble.REG_SP
	default:
		return r
	}
}
