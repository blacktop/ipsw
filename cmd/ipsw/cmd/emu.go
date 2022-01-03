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
	"regexp"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/fatih/color"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

const (
	STACK_BASE = 0x60000000
	STACK_SIZE = 0x00800000
)

type branchType uint8

const (
	DIRCALL   branchType = iota // Direct Branch with link
	INDCALL                     // Indirect Branch with link
	ERET                        // Exception return (indirect)
	DBGEXIT                     // Exit from Debug state
	RET                         // Indirect branch with function return hint
	DIR                         // Direct branch
	INDIR                       // Indirect branch
	EXCEPTION                   // Exception entry
	RESET                       // Reset
	UNKNOWN                     // Other
)

// disassembly colors
var colorOp = color.New(color.Bold).SprintfFunc()
var colorRegs = color.New(color.Bold, color.FgHiBlue).SprintFunc()
var colorImm = color.New(color.Bold, color.FgMagenta).SprintFunc()
var colorAddr = color.New(color.Bold, color.FgMagenta).SprintfFunc()
var colorOpCodes = color.New(color.Faint, color.FgHiWhite).SprintFunc()

var colorHook = color.New(color.Faint, color.FgHiBlue).SprintFunc()
var colorDetails = color.New(color.Italic, color.Faint, color.FgWhite).SprintfFunc()
var intrPrintf = color.New(color.Italic, color.Bold, color.FgHiYellow).PrintfFunc()

func init() {
	rootCmd.AddCommand(emuCmd)

	emuCmd.Flags().Uint64P("vaddr", "a", 0, "Virtual address to start disassembling")
	emuCmd.Flags().Uint64P("count", "c", 0, "Number of instructions to disassemble")

	emuCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

func colorOperands(operands string) string {
	if len(operands) > 0 {
		immMatch := regexp.MustCompile(`#?-?0x[0-9a-z]+`)
		operands = immMatch.ReplaceAllStringFunc(operands, func(s string) string {
			return colorImm(s)
		})
		regMatch := regexp.MustCompile(`\W([wxvbhsdqzp][0-9]{1,2}|(c|s)psr(_c)?|pc|sl|sb|fp|ip|sp|lr|fpsid|fpscr|fpexc)`)
		operands = regMatch.ReplaceAllStringFunc(operands, func(s string) string {
			return string(s[0]) + colorRegs(s[1:])
		})
	}
	return operands
}

func diss(startAddr uint64, data []byte) {
	var instrValue uint32
	var results [1024]byte

	r := bytes.NewReader(data)

	for {
		err := binary.Read(r, binary.LittleEndian, &instrValue)

		if err == io.EOF {
			break
		}

		instruction, err := disassemble.Decompose(startAddr, instrValue, &results)
		if err != nil {
			fmt.Printf("%s:  %s\t%s\t%#-18x ; (%s)\n",
				colorAddr("%#08x", uint64(startAddr)),
				colorOp("%-7s", ".long"),
				colorOpCodes(disassemble.GetOpCodeByteString(instrValue)),
				instrValue,
				err.Error())
		}

		opStr := strings.TrimSpace(strings.TrimPrefix(instruction.String(), instruction.Operation.String()))

		fmt.Printf("%s:  %s   %s %s\n",
			colorAddr("%#08x", uint64(startAddr)),
			colorOpCodes(disassemble.GetOpCodeByteString(instrValue)),
			colorOp("%-7s", instruction.Operation),
			colorOperands(" "+opStr),
		)

		startAddr += uint64(binary.Size(uint32(0)))
	}
}

// var regs = []int{
// 	// ARM64 registers
// uc.ARM64_REG_X0,
// uc.ARM64_REG_X1,
// uc.ARM64_REG_X2,
// uc.ARM64_REG_X3,
// uc.ARM64_REG_X4,
// uc.ARM64_REG_X5,
// uc.ARM64_REG_X6,
// uc.ARM64_REG_X7,
// uc.ARM64_REG_X8,
// uc.ARM64_REG_X9,
// uc.ARM64_REG_X10,
// uc.ARM64_REG_X11,
// uc.ARM64_REG_X12,
// uc.ARM64_REG_X13,
// uc.ARM64_REG_X14,
// uc.ARM64_REG_X15,
// uc.ARM64_REG_X16,
// uc.ARM64_REG_X17,
// uc.ARM64_REG_X18,
// uc.ARM64_REG_X19,
// uc.ARM64_REG_X20,
// uc.ARM64_REG_X21,
// uc.ARM64_REG_X22,
// uc.ARM64_REG_X23,
// uc.ARM64_REG_X24,
// uc.ARM64_REG_X25,
// uc.ARM64_REG_X26,
// uc.ARM64_REG_X27,
// uc.ARM64_REG_X28,
// 	uc.ARM64_REG_X29, // ARM64_REG_FP
// 	uc.ARM64_REG_X30, // ARM64_REG_LR
// 	uc.ARM64_REG_NZCV,
// 	uc.ARM64_REG_SP,
// 	uc.ARM64_REG_WSP,
// 	uc.ARM64_REG_WZR,
// 	uc.ARM64_REG_XZR,
// 	// pseudo registers
// 	uc.ARM64_REG_PC,
// 	uc.ARM64_REG_CPACR_EL1,
// 	// thread registers
// 	uc.ARM64_REG_TPIDR_EL0,
// 	uc.ARM64_REG_TPIDRRO_EL0,
// 	uc.ARM64_REG_TPIDR_EL1,
// 	uc.ARM64_REG_PSTATE,
// 	// exception link registers
// 	uc.ARM64_REG_ELR_EL0,
// 	uc.ARM64_REG_ELR_EL1,
// 	uc.ARM64_REG_ELR_EL2,
// 	uc.ARM64_REG_ELR_EL3,
// 	// stack pointers registers
// 	uc.ARM64_REG_SP_EL0,
// 	uc.ARM64_REG_SP_EL1,
// 	uc.ARM64_REG_SP_EL2,
// 	uc.ARM64_REG_SP_EL3,
// 	// other CP15 registers
// 	uc.ARM64_REG_TTBR0_EL1,
// 	uc.ARM64_REG_TTBR1_EL1,
// 	uc.ARM64_REG_ESR_EL0,
// 	uc.ARM64_REG_ESR_EL1,
// 	uc.ARM64_REG_ESR_EL2,
// 	uc.ARM64_REG_ESR_EL3,
// 	uc.ARM64_REG_FAR_EL0,
// 	uc.ARM64_REG_FAR_EL1,
// 	uc.ARM64_REG_FAR_EL2,
// 	uc.ARM64_REG_FAR_EL3,
// 	uc.ARM64_REG_PAR_EL1,
// 	uc.ARM64_REG_MAIR_EL1,
// 	uc.ARM64_REG_VBAR_EL0,
// 	uc.ARM64_REG_VBAR_EL1,
// 	uc.ARM64_REG_VBAR_EL2,
// 	uc.ARM64_REG_VBAR_EL3,
// }

type registers map[int]uint64

func getState(mu uc.Unicorn) (registers, error) {
	rs := make(map[int]uint64)

	regs := make([]int, uc.ARM64_REG_ENDING-uc.ARM64_REG_INVALID+1)
	for i := range regs {
		regs[i] = uc.ARM64_REG_INVALID + i

	}
	vals, err := mu.RegReadBatch(regs)
	if err != nil {
		return nil, err
	}
	for idx, val := range vals {
		rs[regs[idx]] = val
	}

	return rs, nil
}

func (r registers) String() string {
	return fmt.Sprintf(colorHook("[REGISTERS]\n") +
		colorDetails(
			"     x0: %#-18x  x1: %#-18x  x2: %#-18x  x3: %#-18x\n"+
				"     x4: %#-18x  x5: %#-18x  x6: %#-18x  x7: %#-18x\n"+
				"     x8: %#-18x  x9: %#-18x x10: %#-18x x11: %#-18x\n"+
				"    x12: %#-18x x13: %#-18x x14: %#-18x x15: %#-18x\n"+
				"    x16: %#-18x x17: %#-18x x18: %#-18x x19: %#-18x\n"+
				"    x20: %#-18x x21: %#-18x x22: %#-18x x23: %#-18x\n"+
				"    x24: %#-18x x25: %#-18x x26: %#-18x x27: %#-18x\n"+
				"    x28: %#-18x  fp: %#-18x  lr: %#-18x\n"+
				"     pc: %#-18x  sp: %#-18x cpsr: 0x%08x %s",
			r[uc.ARM64_REG_X0], r[uc.ARM64_REG_X1], r[uc.ARM64_REG_X2], r[uc.ARM64_REG_X3],
			r[uc.ARM64_REG_X4], r[uc.ARM64_REG_X5], r[uc.ARM64_REG_X6], r[uc.ARM64_REG_X7],
			r[uc.ARM64_REG_X8], r[uc.ARM64_REG_X9], r[uc.ARM64_REG_X10], r[uc.ARM64_REG_X11],
			r[uc.ARM64_REG_X12], r[uc.ARM64_REG_X13], r[uc.ARM64_REG_X14], r[uc.ARM64_REG_X15],
			r[uc.ARM64_REG_X16], r[uc.ARM64_REG_X17], r[uc.ARM64_REG_X18], r[uc.ARM64_REG_X19],
			r[uc.ARM64_REG_X20], r[uc.ARM64_REG_X21], r[uc.ARM64_REG_X22], r[uc.ARM64_REG_X23],
			r[uc.ARM64_REG_X24], r[uc.ARM64_REG_X25], r[uc.ARM64_REG_X26], r[uc.ARM64_REG_X27],
			r[uc.ARM64_REG_X28], r[uc.ARM64_REG_FP], r[uc.ARM64_REG_LR],
			r[uc.ARM64_REG_PC], r[uc.ARM64_REG_SP], r[uc.ARM64_REG_PSTATE], pstate(r[uc.ARM64_REG_PSTATE]),
		))
}

func alignDown(addr uint64) uint64 {
	left := addr % 0x1000
	return addr - left
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

type pstate uint32

func (p pstate) N() bool {
	return types.ExtractBits(uint64(p), 31, 1) != 0
}
func (p pstate) Z() bool {
	return types.ExtractBits(uint64(p), 30, 1) != 0
}
func (p pstate) C() bool {
	return types.ExtractBits(uint64(p), 29, 1) != 0
}
func (p pstate) V() bool {
	return types.ExtractBits(uint64(p), 28, 1) != 0
}
func (p pstate) D() bool {
	return types.ExtractBits(uint64(p), 27, 1) != 0
}
func (p pstate) A() bool {
	return types.ExtractBits(uint64(p), 26, 1) != 0
}
func (p pstate) I() bool {
	return types.ExtractBits(uint64(p), 25, 1) != 0
}
func (p pstate) F() bool {
	return types.ExtractBits(uint64(p), 24, 1) != 0
}
func (p pstate) PAN() bool {
	return types.ExtractBits(uint64(p), 23, 1) != 0
}
func (p pstate) UAO() bool {
	return types.ExtractBits(uint64(p), 22, 1) != 0
}
func (p pstate) DIT() bool {
	return types.ExtractBits(uint64(p), 21, 1) != 0
}
func (p pstate) TCO() bool {
	return types.ExtractBits(uint64(p), 20, 1) != 0
}
func (p pstate) BType() branchType {
	return branchType(types.ExtractBits(uint64(p), 19, 2))
}
func (p pstate) SS() bool {
	return types.ExtractBits(uint64(p), 17, 1) != 0
}
func (p pstate) IL() bool {
	return types.ExtractBits(uint64(p), 16, 1) != 0
}
func (p pstate) EL() uint64 {
	return types.ExtractBits(uint64(p), 15, 2)
}
func (p pstate) NRW() bool {
	return types.ExtractBits(uint64(p), 13, 1) != 0
}
func (p pstate) SP() bool {
	return types.ExtractBits(uint64(p), 12, 1) != 0
}
func (p pstate) Q() bool {
	return types.ExtractBits(uint64(p), 11, 1) != 0
}
func (p pstate) GE() bool {
	return types.ExtractBits(uint64(p), 10, 4) != 0
}
func (p pstate) SSBS() bool {
	return types.ExtractBits(uint64(p), 9, 1) != 0
}
func (p pstate) IT() bool {
	return types.ExtractBits(uint64(p), 1, 8) != 0
}
func (p pstate) J() bool {
	return types.ExtractBits(uint64(p), 0, 1) != 0
}
func (p pstate) T() bool {
	return types.ExtractBits(uint64(p), 0, 1) != 0
}
func (p pstate) E() bool {
	return types.ExtractBits(uint64(p), 0, 1) != 0
}
func (p pstate) M() bool {
	return types.ExtractBits(uint64(p), 0, 1) != 0
}

func (p pstate) String() string {
	var flags []string
	if p.N() {
		flags = append(flags, "N")
	}
	if p.Z() {
		flags = append(flags, "Z")
	}
	if p.C() {
		flags = append(flags, "C")
	}
	if p.V() {
		flags = append(flags, "V")
	}
	if p.D() {
		flags = append(flags, "D")
	}
	if p.A() {
		flags = append(flags, "A")
	}
	if p.I() {
		flags = append(flags, "I")
	}
	if p.F() {
		flags = append(flags, "F")
	}
	return colorDetails("[%s]", strings.Join(flags, " "))
}

// func (p pstate) String() string {
// 	return actionColor(
// 		" N: %t, Z: %t, C: %t, V: %t, D: %t, A: %t, I: %t, F: %t\n"+
// 			" PAN: %t, UAO: %t, DIT: %t, TCO: %t, BType: %d, SS: %t, IL: %t\n"+
// 			" EL: %d, 32bit: %t, SP: %t",
// 		p.N(), p.Z(), p.C(), p.V(), p.D(), p.A(), p.I(), p.F(),
// 		p.PAN(), p.UAO(), p.DIT(), p.TCO(), p.BType(), p.SS(), p.IL(),
// 		p.EL(), p.NRW(), p.SP(),
// 	)
// }

// emuCmd represents the emu command
var emuCmd = &cobra.Command{
	Use:           "emu",
	Short:         "🚧 Emulate AARCH64 dyld_shared_cache",
	SilenceUsage:  false,
	SilenceErrors: true,
	Args:          cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		instructions, _ := cmd.Flags().GetUint64("count")
		startAddr, _ := cmd.Flags().GetUint64("vaddr")

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
				fmt.Print(colorHook("[MEM_READ]" + colorDetails(" addr: %#x, size: %d, value: %#x\n", addr64, size, value)))
				// utils.Indent(log.WithFields(log.Fields{"addr": fmt.Sprintf("%#x", addr64), "size": size, "value": value}).Debug, 2)("MEM_READ")
			case uc.MEM_WRITE:
				fmt.Print(colorHook("[MEM_WRITE]" + colorDetails(" addr: %#x, size: %d, value: %#x\n", addr64, size, value)))
				// utils.Indent(log.WithFields(log.Fields{"addr": fmt.Sprintf("%#x", addr64), "size": size, "value": value}).Debug, 2)("MEM_WRITE")
			}
		}, 1, 0); err != nil {
			return fmt.Errorf("failed to register r/w hook: %v", err)
		}
		if _, err := mu.HookAdd(uc.HOOK_MEM_READ_INVALID|uc.HOOK_MEM_WRITE_INVALID|uc.HOOK_MEM_FETCH_INVALID,
			func(mu uc.Unicorn, access int, addr uint64, size int, value int64) bool {
				switch access {
				case uc.MEM_WRITE_UNMAPPED:
					fmt.Print(colorHook("[MEM_WRITE_UNMAPPED]"))
				case uc.MEM_WRITE_PROT:
					fmt.Print(colorHook("[MEM_WRITE_PROT]"))
				case uc.MEM_READ_UNMAPPED:
					fmt.Print(colorHook("[MEM_READ_UNMAPPED]"))
					uuid, off, err := f.GetOffset(f.SlideInfo.SlidePointer(addr))
					if err != nil {
						log.Errorf(err.Error())
						return false
					}
					dat, err := f.ReadBytesForUUID(uuid, int64(off), 0x1000)
					if err != nil {
						log.Errorf(err.Error())
						return false
					}
					if err := mu.MemMap(alignDown(addr), 0x2000); err != nil {
						log.Errorf("failed to memmap at %#x: %v", addr, err)
						return false
					}
					if err := mu.MemWrite(addr, dat); err != nil {
						log.Errorf("failed to mem write at %#x: %v", addr, err)
						return false
					}
					return true
				case uc.MEM_READ_PROT:
					fmt.Print(colorHook("[MEM_READ_PROT]"))
				case uc.MEM_FETCH_UNMAPPED:
					fmt.Print(colorHook("[MEM_FETCH_UNMAPPED]"))
					uuid, off, err := f.GetOffset(f.SlideInfo.SlidePointer(addr))
					if err != nil {
						log.Errorf(err.Error())
						return false
					}
					dat, err := f.ReadBytesForUUID(uuid, int64(off), 0x1000)
					if err != nil {
						log.Errorf(err.Error())
						return false
					}
					if err := mu.MemMap(alignDown(addr), 0x2000); err != nil {
						log.Errorf("failed to memmap at %#x: %v", addr, err)
						return false
					}
					if err := mu.MemWrite(addr, dat); err != nil {
						log.Errorf("failed to mem write at %#x: %v", addr, err)
						return false
					}
					return true
				case uc.MEM_FETCH_PROT:
					fmt.Print(colorHook("[MEM_FETCH_PROT]"))
				default:
					fmt.Print(colorDetails("unknown memory error: %d\n", access))
				}
				fmt.Print(colorDetails(" @ %#x, size=%d, value: %#x\n", addr, size, value))
				return false
			}, 1, 0); err != nil {
			return fmt.Errorf("failed to register mem invalid read/write/fetch hook: %v", err)
		}
		if _, err := mu.HookAdd(uc.HOOK_BLOCK, func(mu uc.Unicorn, addr uint64, size uint32) {
			// metaPrintf("\n[BLOCK] addr: %#x, size: %d\n", addr, size)
			fmt.Println()
		}, 1, 0); err != nil {
			return fmt.Errorf("failed to register mem invalid read/write/fetch hook: %v", err)
		}
		if _, err := mu.HookAdd(uc.HOOK_CODE, func(mu uc.Unicorn, addr uint64, size uint32) {
			// utils.Indent(log.WithFields(log.Fields{"addr": fmt.Sprintf("%#x", addr), "size": size}).Debug, 2)("CODE")
			uuid, soff, err := f.GetOffset(addr)
			if err != nil {
				log.Errorf(err.Error())
				return
			}
			code, err := f.ReadBytesForUUID(uuid, int64(soff), uint64(size))
			if err != nil {
				log.Errorf(err.Error())
				return
			}
			if Verbose {
				regs, err := getState(mu)
				if err != nil {
					log.Errorf(err.Error())
					return
				}
				fmt.Println(regs)
			}
			diss(addr, code)
		}, 1, 0); err != nil {
			return fmt.Errorf("failed to register mem invalid read/write/fetch hook: %v", err)
		}
		if _, err := mu.HookAdd(uc.HOOK_INTR, func(mu uc.Unicorn, intno uint32) {
			intrPrintf("[HOOK_INTR] intno: %d\n", intno)
			log.Fatal("UNHANDLED INTERRUPT")
		}, 1, 0); err != nil {
			return fmt.Errorf("failed to register interrupt hook: %v", err)
		}

		image, err := f.GetImageContainingVMAddr(startAddr)
		if err != nil {
			return err
		}

		m, err := image.GetMacho()
		if err != nil {
			return err
		}
		defer m.Close()

		var code []byte
		if fn, err := m.GetFunctionForVMAddr(startAddr); err == nil {
			uuid, soff, err := f.GetOffset(fn.StartAddr)
			if err != nil {
				return err
			}
			code, err = f.ReadBytesForUUID(uuid, int64(soff), uint64(fn.EndAddr-fn.StartAddr))
			if err != nil {
				return err
			}
			if err := mu.MemMap(alignDown(fn.StartAddr), 0x2000); err != nil {
				return fmt.Errorf("failed to memmap at %#x: %v", fn.StartAddr, err)
			}
			if err := mu.MemWrite(fn.StartAddr, code); err != nil {
				return fmt.Errorf("failed to write mem at %#x: %v", fn.StartAddr, err)
			}
			// diss(fn.StartAddr, code)
		} else {
			log.Warnf("emulating %d instructions at %#x", instructions, startAddr)
			uuid, off, err := f.GetOffset(startAddr)
			if err != nil {
				return err
			}
			code, err = f.ReadBytesForUUID(uuid, int64(off), instructions*4)
			if err != nil {
				return err
			}
			if err := mu.MemMap(alignDown(startAddr), 0x2000); err != nil {
				return fmt.Errorf("failed to memmap at %#x: %v", startAddr, err)
			}
			if err := mu.MemWrite(startAddr, code); err != nil {
				return fmt.Errorf("failed to write mem at %#x: %v", startAddr, err)
			}
			// diss(startAddr, code)
		}

		// initialize stack to 2MBs
		if err := mu.MemMap(STACK_BASE, STACK_SIZE); err != nil {
			return fmt.Errorf("failed to memmap stack at %#x: %v", STACK_BASE, err)
		}
		if err := mu.RegWrite(uc.ARM64_REG_SP, STACK_BASE+STACK_SIZE); err != nil {
			return fmt.Errorf("failed to set SP register to %#x: %v", STACK_BASE+STACK_SIZE, err)
		}

		//***********
		//* EMULATE *
		//***********
		if err := mu.Start(startAddr, startAddr+(instructions*4)); err != nil {
			return fmt.Errorf("failed to emulate: %v", err)
		}

		regs, err := getState(mu)
		if err != nil {
			return fmt.Errorf("failed to register state: %v", err)
		}
		fmt.Println(regs)

		log.Info("Emulation Complete ✅")

		return nil
	},
}
