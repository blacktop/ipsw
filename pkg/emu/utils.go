//go:build unicorn

package emu

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/spf13/cast"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

func (e *Emulation) SetFirstArg(data any) error {
	if err := e.WriteData(STACK_DATA, data); err != nil {
		return fmt.Errorf("failed to write data to %#x: %v", STACK_DATA, err)
	}
	if err := e.mu.RegWrite(uc.ARM64_REG_X0, STACK_DATA); err != nil {
		return fmt.Errorf("failed to set x0 (arg0) register to %#x: %v", STACK_DATA, err)
	}
	return nil
}

func (e *Emulation) SetState(state *State) error {
	// write args to stack
	if len(state.Args) > 8 {
		return fmt.Errorf("too many args: %d, (max 8)", len(state.Args))
	}
	stackArgAddr := uint64(STACK_DATA)
	for idx, arg := range state.Args {
		for _, field := range arg {
			var val any
			switch field.Type {
			case "uint64":
				val = cast.ToUint64(field.Value)
			case "int64":
				val = cast.ToInt64(field.Value)
			case "uint32":
				val = cast.ToUint32(field.Value)
			case "int32":
				val = cast.ToInt32(field.Value)
			case "uint16":
				val = cast.ToUint16(field.Value)
			case "int16":
				val = cast.ToInt16(field.Value)
			case "uint8":
				val = cast.ToUint8(field.Value)
			}
			if err := e.WriteData(stackArgAddr, val); err != nil {
				return fmt.Errorf("failed to write data to %#x: %v", stackArgAddr, err)
			}
			stackArgAddr += uint64(binary.Size(val))
		}
		if err := e.mu.RegWrite(uc.ARM64_REG_X0+idx, STACK_DATA); err != nil { // x0-x7
			return fmt.Errorf("failed to set (arg%d) register to %#x: %v", idx, STACK_DATA, err)
		}
	}

	// TODO: finish writing stack (need to put args somewhere else?)

	// write registers
	for regName, regValue := range state.Registers {
		reg, err := e.GetRegisterByName(regName)
		if err != nil {
			return fmt.Errorf("failed to get register %s: %v", regName, err)
		}
		if err := e.mu.RegWrite(int(reg), regValue); err != nil {
			return fmt.Errorf("failed to set %s register to %#x: %v", regName, regValue, err)
		}
	}

	return nil
}

func (e *Emulation) GetRegisterByName(name string) (int, error) {
	for num, reg := range e.regs {
		if reg.Name == name || reg.Alias == name {
			return num, nil
		}
	}
	return uc.ARM64_REG_INVALID, fmt.Errorf("failed to find register %s", name)
}

func (e *Emulation) ReadSctlrEL1() (uint64, error) {
	// return e.mu.RegRead(uc.ARM64_REG_CP_REG, 1, 0, 3, 0, 0) // FIXME: when unicorn supports this
	panic("not implemented")
}

func (e *Emulation) PutPointer(where uint64, ptr uint64, size uint64) error {
	buf := make([]byte, size)
	if size == 4 {
		binary.LittleEndian.PutUint32(buf, uint32(ptr))
		return e.mu.MemWrite(where, buf)
	} else {
		binary.LittleEndian.PutUint64(buf, ptr)
		return e.mu.MemWrite(where, buf)
	}
}

func (e *Emulation) WriteData(addr uint64, data any) error {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, data)
	return e.mu.MemWrite(addr, buf.Bytes())
}

func GetRandomUint64() uint64 {
	buf := make([]byte, 8)
	rand.Read(buf)
	return binary.LittleEndian.Uint64(buf)
}

// Align returns an aligned memory addr/size to be uses with unicorn MemMap
func Align(addr, size uint64, growl ...bool) (uint64, uint64) {
	to := uint64(UC_MEM_ALIGN)
	mask := ^(to - 1)
	right := addr + size
	right = (right + to - 1) & mask
	addr &= mask
	size = right - addr
	if len(growl) > 0 && growl[0] {
		size = (size + to - 1) & mask
	}
	return addr, size
}

func (e *Emulation) DumpMem(addr uint64, size uint64) error {
	dat, err := e.mu.MemRead(addr, size)
	if err != nil {
		return err
	}
	fmt.Print(utils.HexDump(dat, addr))
	return nil
}

// DumpMemRegions prints emulation memory regions
func (e *Emulation) DumpMemRegions() error {
	memRegs, err := e.mu.MemRegions()
	if err != nil {
		return err
	}
	for _, mr := range memRegs {
		fmt.Printf(
			colorHook("    begin: ") + colorDetails("%#09x", mr.Begin) +
				colorHook(", end: ") + colorDetails("%#09x", mr.End) +
				colorHook(", prot: ") + colorDetails("%s", types.VmProtection(mr.Prot)) +
				colorHook(", size: ") + colorDetails("%#x\n", mr.End-mr.Begin+1),
		)
	}
	return nil
}

func min(a, b uint64) uint64 {
	if a > b {
		return b
	}
	return a
}

func getCode() []byte {
	var code []byte
	a := make([]byte, 4)

	instructions := []uint32{
		3492604664,
		2432795416,
		3535798329,
		2992668666,
	}

	for _, i := range instructions {
		binary.LittleEndian.PutUint32(a, i)
		code = append(code, a...)
	}

	return code
}
