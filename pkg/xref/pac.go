package xref

import "github.com/blacktop/arm64-cgo/disassemble"

// LdrAuth describes a decoded LDRAA/LDRAB (load register, with pointer
// authentication). The immediate offset is already byte-scaled (the encoded
// 10-bit field times 8) and may be negative.
type LdrAuth struct {
	DestReg   disassemble.Register
	BaseReg   disassemble.Register
	Offset    int64
	Writeback bool
	KeyB      bool
}

// IsLdrAuth reports whether op is an authenticated load (LDRAA/LDRAB).
func IsLdrAuth(op disassemble.Operation) bool {
	return op == disassemble.ARM64_LDRAA || op == disassemble.ARM64_LDRAB
}

// DecodeLdrAuth extracts the base register, byte-scaled offset, pre-index
// writeback flag and destination register of an LDRAA/LDRAB instruction. The
// operand shape mirrors an ordinary LDR: op[0] is the destination register and
// op[1] is a memory operand carrying the base register plus the signed offset.
func DecodeLdrAuth(inst *disassemble.Inst) (LdrAuth, bool) {
	if inst == nil {
		return LdrAuth{}, false
	}
	var keyB bool
	switch inst.Operation {
	case disassemble.ARM64_LDRAA:
	case disassemble.ARM64_LDRAB:
		keyB = true
	default:
		return LdrAuth{}, false
	}
	dest, ok := OperandReg(inst, 0)
	if !ok {
		return LdrAuth{}, false
	}
	base, ok := OperandReg(inst, 1)
	if !ok {
		return LdrAuth{}, false
	}
	op := &inst.Operands[1]
	var writeback bool
	switch op.Class {
	case disassemble.MEM_OFFSET:
	case disassemble.MEM_PRE_IDX:
		writeback = true
	default:
		return LdrAuth{}, false
	}
	return LdrAuth{
		DestReg:   dest,
		BaseReg:   base,
		Offset:    int64(op.GetImmediate()),
		Writeback: writeback,
		KeyB:      keyB,
	}, true
}

// LoadWriteback describes a plain LDR/LDUR with pre-index writeback
// (LDR Xt,[Xn,#imm]!): after the load the base register holds Xn+imm. It is how
// a call-site register walk advances a slot address by a byte displacement
// without an authenticated load. Offset is the raw (unscaled) byte immediate and
// may be negative.
type LoadWriteback struct {
	DestReg disassemble.Register
	BaseReg disassemble.Register
	Offset  int64
}

// DecodeLoadPreIndex decodes a plain LDR/LDUR with pre-index writeback and
// returns its destination register, base register and signed byte offset. It
// rejects the plain offset and post-index forms (only the pre-index `!` form
// updates the base before the value is used) and every non-load instruction.
func DecodeLoadPreIndex(inst *disassemble.Inst) (LoadWriteback, bool) {
	if inst == nil {
		return LoadWriteback{}, false
	}
	switch inst.Operation {
	case disassemble.ARM64_LDR, disassemble.ARM64_LDUR:
	default:
		return LoadWriteback{}, false
	}
	dest, ok := OperandReg(inst, 0)
	if !ok {
		return LoadWriteback{}, false
	}
	base, ok := OperandReg(inst, 1)
	if !ok {
		return LoadWriteback{}, false
	}
	op := &inst.Operands[1]
	if op.Class != disassemble.MEM_PRE_IDX {
		return LoadWriteback{}, false
	}
	return LoadWriteback{DestReg: dest, BaseReg: base, Offset: int64(op.GetImmediate())}, true
}

// AuthPtr describes a decoded pointer-authentication instruction
// (AUTDA/AUTDB/AUTIA/AUTIB and their zero-modifier Z forms). It is treated as
// identity-on-pointer for register tracking: DestReg holds both the input and
// output pointer. ModifierReg is only valid when HasModifier is true (the Z
// forms use an implicit zero modifier).
type AuthPtr struct {
	DestReg     disassemble.Register
	ModifierReg disassemble.Register
	HasModifier bool
	Data        bool
	KeyB        bool
}

// IsAuthPtr reports whether op authenticates a pointer in place
// (AUTDA/AUTDB/AUTIA/AUTIB and the AUTDZA/AUTDZB/AUTIZA/AUTIZB Z forms).
func IsAuthPtr(op disassemble.Operation) bool {
	switch op {
	case disassemble.ARM64_AUTDA, disassemble.ARM64_AUTDZA,
		disassemble.ARM64_AUTDB, disassemble.ARM64_AUTDZB,
		disassemble.ARM64_AUTIA, disassemble.ARM64_AUTIZA,
		disassemble.ARM64_AUTIB, disassemble.ARM64_AUTIZB:
		return true
	default:
		return false
	}
}

// DecodeAuthPtr extracts the pointer register being authenticated and the
// modifier register (if any) from an authenticate-pointer instruction.
func DecodeAuthPtr(inst *disassemble.Inst) (AuthPtr, bool) {
	if inst == nil {
		return AuthPtr{}, false
	}
	var data, keyB bool
	switch inst.Operation {
	case disassemble.ARM64_AUTDA, disassemble.ARM64_AUTDZA:
		data = true
	case disassemble.ARM64_AUTDB, disassemble.ARM64_AUTDZB:
		data, keyB = true, true
	case disassemble.ARM64_AUTIA, disassemble.ARM64_AUTIZA:
	case disassemble.ARM64_AUTIB, disassemble.ARM64_AUTIZB:
		keyB = true
	default:
		return AuthPtr{}, false
	}
	dest, ok := OperandReg(inst, 0)
	if !ok {
		return AuthPtr{}, false
	}
	res := AuthPtr{DestReg: dest, ModifierReg: disassemble.REG_NONE, Data: data, KeyB: keyB}
	if mod, ok := OperandReg(inst, 1); ok {
		res.ModifierReg = mod
		res.HasModifier = true
	}
	return res, true
}

// DecodeMovkShift48 recognizes a MOVK #imm16, LSL #48 and returns its
// destination register and raw 16-bit immediate. It reads the operand
// immediate and shift directly so the imm16 is the unshifted discriminator that
// lives in the LSL #48 window; a MOVK at any other shift (e.g. LSL #32) is
// rejected.
func DecodeMovkShift48(inst *disassemble.Inst) (disassemble.Register, uint16, bool) {
	if inst == nil || inst.Operation != disassemble.ARM64_MOVK {
		return disassemble.REG_NONE, 0, false
	}
	dest, ok := OperandReg(inst, 0)
	if !ok || int(inst.NumOps) <= 1 {
		return disassemble.REG_NONE, 0, false
	}
	op := &inst.Operands[1]
	if !op.ShiftValueUsed || op.ShiftValue != 48 {
		return disassemble.REG_NONE, 0, false
	}
	return dest, uint16(op.Immediate), true
}

// AuthCall describes a register-form authenticated indirect call
// (BLRAA/BLRAB). The zero-modifier BLRAAZ/BLRABZ forms carry no modifier
// register and are not decoded here.
type AuthCall struct {
	TargetReg   disassemble.Register
	ModifierReg disassemble.Register
	KeyB        bool
}

// DecodeAuthCallReg extracts the target and modifier registers of a
// register-form BLRAA/BLRAB. It returns false for BLRAAZ/BLRABZ (which have no
// modifier register) and for any non-authenticated-call instruction.
func DecodeAuthCallReg(inst *disassemble.Inst) (AuthCall, bool) {
	if inst == nil {
		return AuthCall{}, false
	}
	var keyB bool
	switch inst.Operation {
	case disassemble.ARM64_BLRAA:
	case disassemble.ARM64_BLRAB:
		keyB = true
	default:
		return AuthCall{}, false
	}
	target, ok := OperandReg(inst, 0)
	if !ok {
		return AuthCall{}, false
	}
	mod, ok := OperandReg(inst, 1)
	if !ok {
		return AuthCall{}, false
	}
	return AuthCall{TargetReg: target, ModifierReg: mod, KeyB: keyB}, true
}
