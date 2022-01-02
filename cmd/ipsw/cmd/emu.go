/*
Copyright © 2022 blacktop

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

func init() {
	rootCmd.AddCommand(emuCmd)
	emuCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

func diss(startAddr uint64, data []byte) {
	var instrValue uint32
	var results [1024]byte

	r := bytes.NewReader(data)
	fmt.Println("[DISASSEMBLY]")
	for {
		err := binary.Read(r, binary.LittleEndian, &instrValue)

		if err == io.EOF {
			break
		}

		instruction, err := disassemble.Disassemble(startAddr, instrValue, &results)
		if err != nil {
			fmt.Printf("%#08x:  %s\t.long\t%#-18x ; (%s)\n", uint64(startAddr), disassemble.GetOpCodeByteString(instrValue), instrValue, err.Error())
		}

		fmt.Printf("%#08x:  %s\t%s\n",
			uint64(startAddr),
			disassemble.GetOpCodeByteString(instrValue),
			instruction)

		startAddr += uint64(binary.Size(uint32(0)))
	}
}

type Regs map[string]uint64

func getState(mu uc.Unicorn) (Regs, error) {
	var err error
	regs := make(Regs)
	regs["x0"], err = mu.RegRead(uc.ARM64_REG_X0)
	if err != nil {
		return nil, err
	}
	regs["x1"], err = mu.RegRead(uc.ARM64_REG_X1)
	if err != nil {
		return nil, err
	}
	regs["x2"], err = mu.RegRead(uc.ARM64_REG_X2)
	if err != nil {
		return nil, err
	}
	regs["x3"], err = mu.RegRead(uc.ARM64_REG_X3)
	if err != nil {
		return nil, err
	}
	regs["x4"], err = mu.RegRead(uc.ARM64_REG_X4)
	if err != nil {
		return nil, err
	}
	regs["x5"], err = mu.RegRead(uc.ARM64_REG_X5)
	if err != nil {
		return nil, err
	}
	regs["x6"], err = mu.RegRead(uc.ARM64_REG_X6)
	if err != nil {
		return nil, err
	}
	regs["x7"], err = mu.RegRead(uc.ARM64_REG_X7)
	if err != nil {
		return nil, err
	}
	regs["x8"], err = mu.RegRead(uc.ARM64_REG_X8)
	if err != nil {
		return nil, err
	}
	regs["x9"], err = mu.RegRead(uc.ARM64_REG_X9)
	if err != nil {
		return nil, err
	}
	regs["x10"], err = mu.RegRead(uc.ARM64_REG_X10)
	if err != nil {
		return nil, err
	}
	regs["x11"], err = mu.RegRead(uc.ARM64_REG_X11)
	if err != nil {
		return nil, err
	}
	regs["x12"], err = mu.RegRead(uc.ARM64_REG_X12)
	if err != nil {
		return nil, err
	}
	regs["x13"], err = mu.RegRead(uc.ARM64_REG_X13)
	if err != nil {
		return nil, err
	}
	regs["x14"], err = mu.RegRead(uc.ARM64_REG_X14)
	if err != nil {
		return nil, err
	}
	regs["x15"], err = mu.RegRead(uc.ARM64_REG_X15)
	if err != nil {
		return nil, err
	}
	regs["x16"], err = mu.RegRead(uc.ARM64_REG_X16)
	if err != nil {
		return nil, err
	}
	regs["x17"], err = mu.RegRead(uc.ARM64_REG_X17)
	if err != nil {
		return nil, err
	}
	regs["x18"], err = mu.RegRead(uc.ARM64_REG_X18)
	if err != nil {
		return nil, err
	}
	regs["x19"], err = mu.RegRead(uc.ARM64_REG_X19)
	if err != nil {
		return nil, err
	}
	regs["x20"], err = mu.RegRead(uc.ARM64_REG_X20)
	if err != nil {
		return nil, err
	}
	regs["x21"], err = mu.RegRead(uc.ARM64_REG_X21)
	if err != nil {
		return nil, err
	}
	regs["x22"], err = mu.RegRead(uc.ARM64_REG_X22)
	if err != nil {
		return nil, err
	}
	regs["x23"], err = mu.RegRead(uc.ARM64_REG_X23)
	if err != nil {
		return nil, err
	}
	regs["x24"], err = mu.RegRead(uc.ARM64_REG_X24)
	if err != nil {
		return nil, err
	}
	regs["x25"], err = mu.RegRead(uc.ARM64_REG_X25)
	if err != nil {
		return nil, err
	}
	regs["x26"], err = mu.RegRead(uc.ARM64_REG_X26)
	if err != nil {
		return nil, err
	}
	regs["x27"], err = mu.RegRead(uc.ARM64_REG_X27)
	if err != nil {
		return nil, err
	}
	regs["x28"], err = mu.RegRead(uc.ARM64_REG_X28)
	if err != nil {
		return nil, err
	}
	regs["fp"], err = mu.RegRead(uc.ARM64_REG_FP)
	if err != nil {
		return nil, err
	}
	regs["lr"], err = mu.RegRead(uc.ARM64_REG_LR)
	if err != nil {
		return nil, err
	}
	regs["sp"], err = mu.RegRead(uc.ARM64_REG_SP)
	if err != nil {
		return nil, err
	}
	regs["pc"], err = mu.RegRead(uc.ARM64_REG_PC)
	if err != nil {
		return nil, err
	}
	regs["cpsr"], err = mu.RegRead(uc.ARM_REG_CPSR)
	if err != nil {
		return nil, err
	}

	return regs, nil
}

func (r Regs) String() string {
	return fmt.Sprintf(
		"[REGISTERS]\n"+
			" x0: %#-18x  x1: %#-18x  x2: %#-18x  x3: %#-18x\n"+
			" x4: %#-18x  x5: %#-18x  x6: %#-18x  x7: %#-18x\n"+
			" x8: %#-18x  x9: %#-18x x10: %#-18x x11: %#-18x\n"+
			"x12: %#-18x x13: %#-18x x14: %#-18x x15: %#-18x\n"+
			"x16: %#-18x x17: %#-18x x18: %#-18x x19: %#-18x\n"+
			"x20: %#-18x x21: %#-18x x22: %#-18x x23: %#-18x\n"+
			"x24: %#-18x x25: %#-18x x26: %#-18x x27: %#-18x\n"+
			"x28: %#-18x x29: %#-18x x30: %#-18x\n"+
			" pc: %#-18x  sp: %#-18x cpsr: 0x%08x",
		r["x0"], r["x1"], r["x2"], r["x3"],
		r["x4"], r["x5"], r["x6"], r["x7"],
		r["x8"], r["x9"], r["x10"], r["x11"],
		r["x12"], r["x13"], r["x14"], r["x15"],
		r["x16"], r["x17"], r["x18"], r["x19"],
		r["x20"], r["x21"], r["x22"], r["x23"],
		r["x24"], r["x25"], r["x26"], r["x27"],
		r["x28"], r["fp"], r["lr"],
		r["pc"], r["sp"], r["cpsr"],
	)
}

func alignDown(addr uint64) uint64 {
	left := addr % 0x1000
	return addr - left
}

func getCode() []byte {
	var code []byte
	a := make([]byte, 4)
	instructions := []uint32{
		3492604664, // adrp    x24, 0x1da0ba000
		2432795416, // add     x24, x24, #0x60 ; ___CFRuntimeClassTables
		3535798329, // mov     x25, #0x100000000
		2992668666, // mov     x26, #0xffffffff00000000
	}
	for _, i := range instructions {
		binary.LittleEndian.PutUint32(a, i)
		code = append(code, a...)
	}

	return code
}

// emuCmd represents the emu command
var emuCmd = &cobra.Command{
	Use:           "emu",
	Short:         "🚧 Emulate AARCH64 dyld_shared_cache",
	SilenceUsage:  false,
	SilenceErrors: true,
	Args:          cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		dscPath := filepath.Clean(args[0])

		fileInfo, err := os.Lstat(dscPath)
		if err != nil {
			return fmt.Errorf("file %s does not exist", dscPath)
		}

		// Check if file is a symlink
		if fileInfo.Mode()&os.ModeSymlink != 0 {
			symlinkPath, err := os.Readlink(dscPath)
			if err != nil {
				return errors.Wrapf(err, "failed to read symlink %s", dscPath)
			}
			// TODO: this seems like it would break
			linkParent := filepath.Dir(dscPath)
			linkRoot := filepath.Dir(linkParent)

			dscPath = filepath.Join(linkRoot, symlinkPath)
		}

		f, err := dyld.Open(dscPath)
		if err != nil {
			return err
		}
		defer f.Close()

		mu, _ := uc.NewUnicorn(uc.ARCH_ARM64, uc.MODE_ARM)

		if _, err := mu.HookAdd(uc.HOOK_MEM_READ|uc.HOOK_MEM_WRITE, func(mu uc.Unicorn, access int, addr64 uint64, size int, value int64) {
			switch access {
			case uc.MEM_READ:
				fmt.Printf("[MEM_READ] addr: %#x, size: %d, value: %#x\n", addr64, size, value)
			case uc.MEM_WRITE:
				fmt.Printf("[MEM_WRITE] addr: %#x, size: %d, value: %#x\n", addr64, size, value)
			}
		}, 1, 0); err != nil {
			panic(err)
		}
		invalid := uc.HOOK_MEM_READ_INVALID | uc.HOOK_MEM_WRITE_INVALID | uc.HOOK_MEM_FETCH_INVALID
		if _, err := mu.HookAdd(invalid, func(mu uc.Unicorn, access int, addr uint64, size int, value int64) bool {
			switch access {
			case uc.MEM_WRITE_UNMAPPED:
				fmt.Printf("[MEM_WRITE_UNMAPPED]")
			case uc.MEM_WRITE_PROT:
				fmt.Printf("[MEM_WRITE_PROT]")
			case uc.MEM_READ_UNMAPPED:
				fmt.Printf("[MEM_READ_UNMAPPED]")
				uuid, off, err := f.GetOffset(addr)
				if err != nil {
					panic(err)
				}
				dat, err := f.ReadBytesForUUID(uuid, int64(off), 0x1000)
				if err != nil {
					panic(err)
				}
				if err := mu.MemMap(alignDown(addr), 0x2000); err != nil {
					panic(err)
				}
				if err := mu.MemWrite(addr, dat); err != nil {
					panic(err)
				}
				return true
			case uc.MEM_READ_PROT:
				fmt.Printf("[MEM_READ_PROT]")
			case uc.MEM_FETCH_UNMAPPED:
				fmt.Printf("[MEM_FETCH_UNMAPPED]")
			case uc.MEM_FETCH_PROT:
				fmt.Printf("[MEM_FETCH_PROT]")
			default:
				fmt.Printf("unknown memory error: %d", access)
			}
			fmt.Printf(" @ %#x, size=%d, value: %#x\n", addr, size, value)
			return false
		}, 1, 0); err != nil {
			panic(err)
		}

		startAddr := uint64(0x18035c834)

		code := getCode()

		diss(startAddr, code)

		if err := mu.MemMap(alignDown(startAddr), 0x2000); err != nil {
			panic(err)
		}
		if err := mu.MemWrite(startAddr, code); err != nil {
			panic(err)
		}
		if err := mu.Start(startAddr, startAddr+uint64(len(code))); err != nil {
			panic(err)
		}

		regs, err := getState(mu)
		if err != nil {
			return err
		}

		fmt.Println(regs)

		return nil
	},
}
