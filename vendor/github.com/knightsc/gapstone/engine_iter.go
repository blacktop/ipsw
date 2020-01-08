// +build go1.7

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

// Disassemble a []byte full of opcodes.
//   * address - Address of the first instruction in the given code buffer.
//
// Underlying C resources are automatically free'd by this function.
func (e *Engine) DisasmIter(input []byte, address uint64) <-chan Instruction {
	out := make(chan Instruction, 1)
	go func() {
		defer close(out)
		insn := C.cs_malloc(e.handle)
		defer C.cs_free(insn, C.size_t(1))

		var bptr *C.uint8_t = (*C.uint8_t)(C.CBytes(input))
		defer C.free(unsafe.Pointer(bptr))

		ilen := C.size_t(len(input))
		addr := C.uint64_t(address)
		// Create a slice, and reflect its header
		var insns []C.cs_insn
		h := (*reflect.SliceHeader)(unsafe.Pointer(&insns))
		// Manually fill in the ptr, len and cap from the raw C data
		h.Data = uintptr(unsafe.Pointer(insn))
		h.Len = int(1)
		h.Cap = int(1)

		for C.cs_disasm_iter(
			e.handle,
			&bptr,
			&ilen,
			&addr,
			insn,
		) {

			switch e.arch {
			case CS_ARCH_ARM:
				out <- decomposeArm(e, insns)[0]
			case CS_ARCH_ARM64:
				out <- decomposeArm64(e, insns)[0]
			case CS_ARCH_MIPS:
				out <- decomposeMips(e, insns)[0]
			case CS_ARCH_X86:
				out <- decomposeX86(e, insns)[0]
			case CS_ARCH_PPC:
				out <- decomposePPC(e, insns)[0]
			case CS_ARCH_SYSZ:
				out <- decomposeSysZ(e, insns)[0]
			case CS_ARCH_SPARC:
				out <- decomposeSparc(e, insns)[0]
			case CS_ARCH_XCORE:
				out <- decomposeXcore(e, insns)[0]
			default:
				return
			}
		}
		return
	}()
	return out
}
