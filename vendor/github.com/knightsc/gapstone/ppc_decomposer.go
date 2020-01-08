/*
Gapstone is a Go binding for the Capstone disassembly library. For examples,
try reading the *_test.go files.

	Library Author: Nguyen Anh Quynh
	Binding Author: Ben Nagy
	License: BSD style - see LICENSE file for details
    (c) 2013 COSEINC. All Rights Reserved.
*/

package gapstone

// #cgo LDFLAGS: -lcapstone
// #cgo freebsd CFLAGS: -I/usr/local/include
// #cgo freebsd LDFLAGS: -L/usr/local/lib
// #include <stdlib.h>
// #include <capstone/capstone.h>
import "C"

import (
	"reflect"
	"unsafe"
)

// Accessed via insn.PPC.XXX
type PPCInstruction struct {
	BC        int
	BH        int
	UpdateCR0 bool
	Operands  []PPCOperand
}

// Number of Operands of a given PPC_OP_* type
func (insn PPCInstruction) OpCount(optype uint) int {
	count := 0
	for _, op := range insn.Operands {
		if op.Type == optype {
			count++
		}
	}
	return count
}

type PPCOperand struct {
	Type uint // PPC_OP_* - determines which field is set below
	Reg  uint
	Imm  int64
	Mem  PPCMemoryOperand
	CRX  PPCCRXOperand
}

type PPCMemoryOperand struct {
	Base uint
	Disp int
}

type PPCCRXOperand struct {
	Scale uint
	Reg   uint
	Cond  uint
}

func fillPPCHeader(raw C.cs_insn, insn *Instruction) {

	if raw.detail == nil {
		return
	}

	// Cast the cs_detail union
	cs_ppc := (*C.cs_ppc)(unsafe.Pointer(&raw.detail.anon0[0]))

	ppc := PPCInstruction{
		BC:        int(cs_ppc.bc),
		BH:        int(cs_ppc.bh),
		UpdateCR0: bool(cs_ppc.update_cr0),
	}

	// Cast the op_info to a []C.cs_ppc_op
	var ops []C.cs_ppc_op
	oih := (*reflect.SliceHeader)(unsafe.Pointer(&ops))
	oih.Data = uintptr(unsafe.Pointer(&cs_ppc.operands[0]))
	oih.Len = int(cs_ppc.op_count)
	oih.Cap = int(cs_ppc.op_count)

	// Create the Go object for each operand
	for _, cop := range ops {

		if cop._type == PPC_OP_INVALID {
			break
		}

		gop := new(PPCOperand)
		gop.Type = uint(cop._type)

		switch cop._type {
		// fake a union by setting only the correct struct member
		case PPC_OP_IMM:
			gop.Imm = int64(*(*C.int32_t)(unsafe.Pointer(&cop.anon0[0])))
		case PPC_OP_REG:
			gop.Reg = uint(*(*C.uint)(unsafe.Pointer(&cop.anon0[0])))
		case PPC_OP_MEM:
			cmop := (*C.ppc_op_mem)(unsafe.Pointer(&cop.anon0[0]))
			gop.Mem = PPCMemoryOperand{
				Base: uint(cmop.base),
				Disp: int(cmop.disp),
			}
		case PPC_OP_CRX:
			ccrxop := (*C.ppc_op_crx)(unsafe.Pointer(&cop.anon0[0]))
			gop.CRX = PPCCRXOperand{
				Scale: uint(ccrxop.scale),
				Reg:   uint(ccrxop.reg),
				Cond:  uint(ccrxop.cond),
			}

		}

		ppc.Operands = append(ppc.Operands, *gop)

	}
	insn.PPC = &ppc
}

func decomposePPC(e *Engine, raws []C.cs_insn) []Instruction {
	decomposed := []Instruction{}
	for _, raw := range raws {
		decomp := new(Instruction)
		fillGenericHeader(e, raw, decomp)
		fillPPCHeader(raw, decomp)
		decomposed = append(decomposed, *decomp)
	}
	return decomposed
}
