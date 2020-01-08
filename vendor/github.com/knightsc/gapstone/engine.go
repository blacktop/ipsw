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
// extern size_t trampoline(uint8_t *buffer, size_t buflen, size_t offset, void *user_data);
import "C"

import (
	"fmt"
	"reflect"
	"unsafe"
)

type Errno int

func (e Errno) Error() string {
	s := C.GoString(C.cs_strerror(C.cs_err(e)))
	if s == "" {
		return fmt.Sprintf("Internal Error: No Error string for Errno %v", e)
	}
	return s
}

var (
	ErrOK       = Errno(0)  // No error: everything was fine
	ErrMem      = Errno(1)  // Out-Of-Memory error: cs_open(), cs_disasm()
	ErrArch     = Errno(2)  // Unsupported architecture: cs_open()
	ErrHandle   = Errno(3)  // Invalid handle: cs_op_count(), cs_op_index()
	ErrCsh      = Errno(4)  // Invalid csh argument: cs_close(), cs_errno(), cs_option()
	ErrMode     = Errno(5)  // Invalid/unsupported mode: cs_open()
	ErrOption   = Errno(6)  // Invalid/unsupported option: cs_option()
	ErrDetail   = Errno(7)  // Information is unavailable because detail option is OFF
	ErrMemSetup = Errno(8)  // Dynamic memory management uninitialized (see CS_OPT_MEM)
	ErrVersion  = Errno(9)  // Unsupported version (bindings)
	ErrDiet     = Errno(10) // Access irrelevant data in "diet" engine
	ErrSkipdata = Errno(11) // Access irrelevant data for "data" instruction in SKIPDATA mode
	ErrX86ATT   = Errno(12) // X86 AT&T syntax is unsupported (opt-out at compile time)
	ErrX86Intel = Errno(13) // X86 Intel syntax is unsupported (opt-out at compile time)

)

// Since this is a build-time option for the C lib, it seems logical to have
// this as a static flag.
// Diet Mode Changes:
// - No regs_read, regs_written or groups
// - No response to reg_name or insn_name
// - No mnemonic or op_str
// If you want to see any operands in diet mode, then you need CS_DETAIL.
var dietMode = bool(C.cs_support(CS_SUPPORT_DIET))

// The arch and mode given at create time will determine how code is
// disassembled. After use you must close an Engine with engine.Close() to allow
// the C lib to free resources.
type Engine struct {
	handle   C.csh
	arch     int
	mode     int
	skipdata *C.cs_opt_skipdata
}

// Information that exists for every Instruction, regardless of arch.
// Structure members here will be promoted, so every Instruction will have
// them available. Check the constants for each architecture for available
// Instruction groups etc.
type InstructionHeader struct {
	Id      uint   // Internal id for this instruction. Subject to change.
	Address uint   // Nominal address ($ip) of this instruction
	Size    uint   // Size of the instruction, in bytes
	Bytes   []byte // Raw Instruction bytes
	// Not available in diet mode ( capstone built with CAPSTONE_DIET=yes )
	Mnemonic string // Ascii text of instruction mnemonic
	OpStr    string // Ascii text of instruction operands - Syntax depends on CS_OPT_SYNTAX
	// Not available without the decomposer. BE CAREFUL! By default,
	// CS_OPT_DETAIL is set to CS_OPT_OFF so the result of accessing these
	// members is undefined.
	AllRegistersRead    []uint // List of implicit and explicit registers read by this instruction
	AllRegistersWritten []uint // List of implicit and explicit registers written by this instruction
	RegistersRead       []uint // List of implicit registers read by this instruction
	RegistersWritten    []uint // List of implicit registers written by this instruction
	Groups              []uint // List of *_GRP_* groups this instruction belongs to.
}

// arch specific information will be filled in for exactly one of the
// substructures. Eg, an Engine created with New(CS_ARCH_ARM, CS_MODE_ARM) will
// fill in only the Arm structure member.
type Instruction struct {
	InstructionHeader
	X86   *X86Instruction
	Arm64 *Arm64Instruction
	Arm   *ArmInstruction
	Mips  *MipsInstruction
	PPC   *PPCInstruction
	Sparc *SparcInstruction
	SysZ  *SysZInstruction
	Xcore *XcoreInstruction
}

// Called by the arch specific decomposers
func fillGenericHeader(e *Engine, raw C.cs_insn, insn *Instruction) {

	insn.Id = uint(raw.id)
	insn.Address = uint(raw.address)
	insn.Size = uint(raw.size)

	if !dietMode {
		insn.Mnemonic = C.GoString(&raw.mnemonic[0])
		insn.OpStr = C.GoString(&raw.op_str[0])
	}

	bslice := make([]byte, raw.size)
	for i := 0; i < int(raw.size); i++ {
		bslice[i] = byte(raw.bytes[i])
	}
	insn.Bytes = bslice

	if raw.detail != nil && !dietMode {
		for i := 0; i < int(raw.detail.regs_read_count); i++ {
			insn.RegistersRead = append(insn.RegistersRead, uint(raw.detail.regs_read[i]))
		}

		for i := 0; i < int(raw.detail.regs_write_count); i++ {
			insn.RegistersWritten = append(insn.RegistersWritten, uint(raw.detail.regs_write[i]))
		}

		for i := 0; i < int(raw.detail.groups_count); i++ {
			insn.Groups = append(insn.Groups, uint(raw.detail.groups[i]))
		}

		var regsRead C.cs_regs
		var regsReadCount C.uint8_t
		var regsWrite C.cs_regs
		var regsWriteCount C.uint8_t
		res := C.cs_regs_access(
			e.handle,
			&raw,
			&regsRead[0],
			&regsReadCount,
			&regsWrite[0],
			&regsWriteCount)

		if Errno(res) == ErrOK {
			for i := 0; i < int(regsReadCount); i++ {
				insn.AllRegistersRead = append(insn.AllRegistersRead, uint(regsRead[i]))
			}

			for i := 0; i < int(regsWriteCount); i++ {
				insn.AllRegistersWritten = append(insn.AllRegistersWritten, uint(regsWrite[i]))
			}
		}
	}

}

// Close the underlying C handle and resources used by this Engine
func (e *Engine) Close() error {
	res := C.cs_close(&e.handle)
	if e.skipdata != nil {
		C.free(unsafe.Pointer(e.skipdata.mnemonic))
	}
	return Errno(res)
}

// Accessor for the Engine architecture CS_ARCH_*
func (e *Engine) Arch() int { return e.arch }

// Accessor for the Engine mode CS_MODE_*
func (e *Engine) Mode() int { return e.mode }

// Check if a particular arch is supported by this engine.
// To verify if this engine supports everything, use CS_ARCH_ALL
func (e *Engine) Support(arch int) bool { return bool(C.cs_support(C.int(arch))) }

// Version information.
func (e *Engine) Version() (maj, min int) {
	C.cs_version((*C.int)(unsafe.Pointer(&maj)), (*C.int)(unsafe.Pointer(&min)))
	return
}

// Getter for the last Errno from the engine. Normal code shouldn't need to
// access this directly, but it's exported just in case.
func (e *Engine) Errno() error { return Errno(C.cs_errno(e.handle)) }

// The arch is implicit in the Engine. Accepts either a constant like ARM_REG_R0
// or insn.Arm.Operands[0].Reg, or anything that refers to a Register like
// insn.X86.SibBase etc
//
// WARNING: Always returns "" if capstone built with CAPSTONE_DIET
func (e *Engine) RegName(reg uint) string {
	if dietMode {
		return ""
	}
	return C.GoString(C.cs_reg_name(e.handle, C.uint(reg)))
}

// The arch is implicit in the Engine. Accepts a constant like
// ARM_INSN_ADD, or insn.Id
//
// WARNING: Always returns "" if capstone built with CAPSTONE_DIET
func (e *Engine) InsnName(insn uint) string {
	if dietMode {
		return ""
	}
	return C.GoString(C.cs_insn_name(e.handle, C.uint(insn)))
}

// The arch is implicit in the Engine. Accepts a constant like
// ARM_GRP_JUMP, or insn.Groups[0]
//
// WARNING: Always returns "" if capstone built with CAPSTONE_DIET
func (e *Engine) GroupName(grp uint) string {
	if dietMode {
		return ""
	}
	return C.GoString(C.cs_group_name(e.handle, C.uint(grp)))
}

// Setter for Engine options CS_OPT_*
func (e *Engine) SetOption(ty, value uint) error {
	res := C.cs_option(
		e.handle,
		C.cs_opt_type(ty),
		C.size_t(value),
	)

	if Errno(res) == ErrOK {
		return nil
	}
	return Errno(res)
}

// Disassemble a []byte full of opcodes.
//   * address - Address of the first instruction in the given code buffer.
//   * count - Number of instructions to disassemble, 0 to disassemble the whole []byte
//
// Underlying C resources are automatically free'd by this function.
func (e *Engine) Disasm(input []byte, address, count uint64) ([]Instruction, error) {

	var insn *C.cs_insn
	bptr := (*C.uint8_t)(unsafe.Pointer(&input[0]))
	disassembled := C.cs_disasm(
		e.handle,
		bptr,
		C.size_t(len(input)),
		C.uint64_t(address),
		C.size_t(count),
		&insn,
	)

	if disassembled > 0 {
		defer C.cs_free((*C.cs_insn)(unsafe.Pointer(insn)), C.size_t(disassembled))
		// Create a slice, and reflect its header
		var insns []C.cs_insn
		h := (*reflect.SliceHeader)(unsafe.Pointer(&insns))
		// Manually fill in the ptr, len and cap from the raw C data
		h.Data = uintptr(unsafe.Pointer(insn))
		h.Len = int(disassembled)
		h.Cap = int(disassembled)

		switch e.arch {
		case CS_ARCH_ARM:
			return decomposeArm(e, insns), nil
		case CS_ARCH_ARM64:
			return decomposeArm64(e, insns), nil
		case CS_ARCH_MIPS:
			return decomposeMips(e, insns), nil
		case CS_ARCH_X86:
			return decomposeX86(e, insns), nil
		case CS_ARCH_PPC:
			return decomposePPC(e, insns), nil
		case CS_ARCH_SYSZ:
			return decomposeSysZ(e, insns), nil
		case CS_ARCH_SPARC:
			return decomposeSparc(e, insns), nil
		case CS_ARCH_XCORE:
			return decomposeXcore(e, insns), nil
		default:
			return decomposeGeneric(e, insns), nil
		}
	}
	return []Instruction{}, e.Errno()
}

func decomposeGeneric(e *Engine, raws []C.cs_insn) []Instruction {
	decomposed := []Instruction{}
	for _, raw := range raws {
		decomp := new(Instruction)
		fillGenericHeader(e, raw, decomp)
		decomposed = append(decomposed, *decomp)
	}
	return decomposed
}

// user callback function prototype
type SkipDataCB func(buffer []byte, offset int, userData interface{}) int

// configuration options for CS_OPT_SKIPDATA, passed via SkipDataStart()
type SkipDataConfig struct {
	Mnemonic string
	Callback SkipDataCB
	UserData interface{}
}

type cbWrapper struct {
	fn SkipDataCB
	ud interface{}
}

// Enables capstone CS_OPT_SKIPDATA. If no SkipDataConfig is passed ( nil )
// the default behaviour will be enabled. It is valid to pass any combination
// of the SkipDataConfig options, although UserData without a Callback will be
// ignored.
func (e *Engine) SkipDataStart(config *SkipDataConfig) {

	if config != nil {

		e.skipdata = &C.cs_opt_skipdata{}

		if config.Callback != nil {
			e.skipdata.callback = (C.cs_skipdata_cb_t)(C.trampoline)
			// Happily, we can use the opaque user_data pointer in C to hold both
			// the Go callback function and the Go userData
			e.skipdata.user_data = unsafe.Pointer(
				&cbWrapper{
					fn: config.Callback,
					ud: config.UserData,
				},
			)
		}

		if config.Mnemonic != "" {
			e.skipdata.mnemonic = C.CString(config.Mnemonic)
		} else {
			e.skipdata.mnemonic = C.CString(".byte")
		}

		C.cs_option(e.handle, CS_OPT_SKIPDATA_SETUP, C.size_t(uintptr(unsafe.Pointer(e.skipdata))))
	}

	// If there's no config, just turn on skipdata with the default behaviour
	C.cs_option(e.handle, CS_OPT_SKIPDATA, CS_OPT_ON)
}

// Disable CS_OPT_SKIPDATA. Removes any registered callbacks and frees
// resources.
func (e *Engine) SkipDataStop() {
	C.cs_option(e.handle, CS_OPT_SKIPDATA, CS_OPT_OFF)
	if e.skipdata == nil {
		return
	}
	C.free(unsafe.Pointer(e.skipdata.mnemonic))
	e.skipdata = nil
}

// Create a new Engine with the specified arch and mode
func New(arch int, mode int) (Engine, error) {
	var handle C.csh
	res := C.cs_open(C.cs_arch(arch), C.cs_mode(mode), &handle)
	if Errno(res) == ErrOK {
		return Engine{handle, arch, mode, nil}, nil
	}
	return Engine{0, CS_ARCH_MAX, 0, nil}, Errno(res)
}
