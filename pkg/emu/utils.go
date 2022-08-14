//go:build unicorn

package emu

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/utils"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

func (e *Emulation) SetFirstArg(data interface{}) error {
	if err := e.WriteData(STACK_DATA, data); err != nil {
		return fmt.Errorf("failed to write data to %#x: %v", STACK_DATA, err)
	}
	if err := e.mu.RegWrite(uc.ARM64_REG_X0, STACK_DATA); err != nil {
		return fmt.Errorf("failed to set x0 (arg0) register to %#x: %v", STACK_DATA, err)
	}
	return nil
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

func (e *Emulation) WriteData(addr uint64, data interface{}) error {
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
