/*
Copyright © 2019 blacktop

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
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-arm64"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/demangle"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	// "github.com/knightsc/gapstone"
)

var (
	symbolName   string
	demangleFlag bool
)

func init() {
	rootCmd.AddCommand(disCmd)

	disCmd.Flags().StringVarP(&symbolName, "symbol", "s", "", "Function to disassemble")
	disCmd.PersistentFlags().Uint64P("vaddr", "a", 0, "Virtual address to start disassembling")
	disCmd.PersistentFlags().Uint64P("instrs", "i", 20, "Number of instructions to disassemble")
	disCmd.Flags().BoolVarP(&demangleFlag, "demangle", "d", false, "Demandle symbol names")
	disCmd.MarkZshCompPositionalArgumentFile(1)
}

func hex2int(hexStr string) uint64 {
	cleaned := strings.Replace(hexStr, "#0x", "", -1)
	result, _ := strconv.ParseUint(cleaned, 16, 64)
	return uint64(result)
}

// Demangle a string just as the GNU c++filt program does.
func doDemangle(name string) string {
	var deStr string

	skip := 0
	if name[0] == '.' || name[0] == '$' {
		skip++
	}
	if name[skip] == '_' {
		skip++
	}
	result := demangle.Filter(name[skip:])
	if result == name[skip:] {
		deStr += name
	} else {
		if name[0] == '.' {
			deStr += "."
		}
		deStr += result
	}
	return deStr
}

func isFunctionStart(starts []uint64, addr uint64) uint64 {
	i := sort.Search(len(starts), func(i int) bool { return starts[i] >= addr })
	if i < len(starts) && starts[i] == addr {
		return starts[i+1] - addr
	}
	return 0
}

func pad(length int) string {
	if length > 0 {
		return strings.Repeat(" ", length)
	}
	return " "
}

// disCmd represents the dis command
var disCmd = &cobra.Command{
	Use:   "disass",
	Short: "Disassemble ARM binaries at address or symbol",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var data []byte
		var startAddr uint64

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		m, err := macho.Open(args[0])
		if err != nil {
			return errors.Wrapf(err, "%s appears to not be a valid MachO", args[0])
		}

		instructions, _ := cmd.Flags().GetUint64("instrs")

		funcStarts := m.FunctionStarts()

		if len(symbolName) > 0 {
			startAddr, err = m.FindSymbolAddress(symbolName)
			if err != nil {
				return err
			}
		} else {
			startAddr, _ = cmd.Flags().GetUint64("vaddr")
			if startAddr == 0 {
				return fmt.Errorf("you must supply a vaddr to disassemble at")
			}
		}

		// Set number of bytes to disassemble either instrs or function size if supplied symbol
		disassSize := 4 * instructions
		if funcStarts != nil && startAddr > 0 {
			funcSize := isFunctionStart(funcStarts, startAddr)
			if funcSize != 0 && instructions < funcSize {
				disassSize = funcSize
			}
		}
		data = make([]byte, disassSize)

		found := false
		for _, sec := range m.Sections {
			// if sec.Name == "__text" {
			if sec.Addr <= startAddr && startAddr < (sec.Addr+sec.Size) {
				found = true

				memOffset := startAddr - sec.Addr
				if instructions*4 > sec.Size-memOffset {
					data = make([]byte, sec.Size-memOffset)
				}

				_, err := sec.ReadAt(data, int64(memOffset))
				if err != nil {
					return err
				}

				break
			}
			// }
		}

		if !found {
			return fmt.Errorf("supplied vaddr not found in any __text section")
		}

		for i := range arm64.Disassemble(bytes.NewReader(data), arm64.Options{StartAddress: int64(startAddr)}) {
			// check for start of a new function
			if funcStarts != nil && isFunctionStart(funcStarts, i.Instruction.Address()) != 0 {
				syms, err := m.FindAddressSymbols(i.Instruction.Address())
				if len(syms) > 1 {
					log.Warnf("found more than one symbol at address 0x%x, %v", i.Instruction.Address(), syms)
				}
				if err == nil {
					var symName string
					if demangleFlag {
						symName = doDemangle(syms[0].Name)
					} else {
						for _, sym := range syms {
							if len(sym.Name) > 0 {
								symName = sym.Name
							}
						}
					}
					fmt.Printf("\n%s:\n", symName)
				} else {
					fmt.Printf("\nfunc_%x:\n", i.Instruction.Address())
				}
			}

			// lookup adrp/ldr or add address as a cstring or symbol name
			// if Verbose && (insn.Mnemonic == "ldr" || insn.Mnemonic == "add") && insns[i-1].Mnemonic == "adrp" {
			// 	if insn.Arm64.Operands != nil && len(insn.Arm64.Operands) > 1 {
			// 		if insns[i-1].Arm64.Operands != nil && len(insns[i-1].Arm64.Operands) > 1 {
			// 			adrpRegister := insns[i-1].Arm64.Operands[0].Reg
			// 			adrpImm := insns[i-1].Arm64.Operands[1].Imm
			// 			if insn.Mnemonic == "ldr" && adrpRegister == insn.Arm64.Operands[1].Mem.Base {
			// 				adrpImm += int64(insn.Arm64.Operands[1].Mem.Disp)
			// 			} else if insn.Mnemonic == "add" && adrpRegister == insn.Arm64.Operands[0].Reg {
			// 				adrpImm += insn.Arm64.Operands[2].Imm
			// 			}
			// 			// markup disassemble with label comment
			// 			syms, err := m.FindAddressSymbols(uint64(adrpImm))
			// 			if len(syms) > 1 {
			// 				log.Warnf("found more than one symbol at address 0x%x, %v", uint64(adrpImm), syms)
			// 			}
			// 			if err == nil {
			// 				var symName string
			// 				if demangleFlag {
			// 					symName = doDemangle(syms[0].Name)
			// 				}
			// 				insn.OpStr += fmt.Sprintf(" // %s", symName)
			// 			} else {
			// 				cstr, err := m.GetCString(uint64(adrpImm))
			// 				if err == nil {
			// 					insn.OpStr += fmt.Sprintf(" // %s", cstr)
			// 				}
			// 			}
			// 		}
			// 	}
			// }

			// // check if branch location is a function
			// if strings.HasPrefix(insn.Mnemonic, "b") && strings.HasPrefix(insn.OpStr, "#0x") {
			// 	if insn.Arm64.Operands != nil && len(insn.Arm64.Operands) > 0 {
			// 		syms, err := m.FindAddressSymbols(uint64(insn.Arm64.Operands[0].Imm))
			// 		if len(syms) > 1 {
			// 			log.Warnf("found more than one symbol at address 0x%x, %v", uint64(insn.Arm64.Operands[0].Imm), syms)
			// 		}
			// 		if err == nil {
			// 			var symName string
			// 			if demangleFlag {
			// 				symName = doDemangle(syms[0].Name)
			// 			}
			// 			insn.OpStr = symName
			// 		}
			// 	}
			// }
			fmt.Printf("%#08x:  %s\t%s%s%s\n", i.Instruction.Address(), i.Instruction.OpCodes(), i.Instruction.Operation(), pad(10-len(i.Instruction.Operation().String())), i.Instruction.OpStr())
		}

		// fmt.Println("CAPSTONE====================================================")
		// engine, err := gapstone.New(
		// 	gapstone.CS_ARCH_ARM64,
		// 	gapstone.CS_MODE_ARM,
		// )
		// if err != nil {
		// 	return errors.Wrapf(err, "failed to create capstone engine")
		// }

		// // turn on instruction details
		// engine.SetOption(gapstone.CS_OPT_DETAIL, gapstone.CS_OPT_ON)

		// insns, err := engine.Disasm(
		// 	data,
		// 	startAddr,
		// 	0, // insns to disassemble, 0 for all
		// )
		// if err != nil {
		// 	return errors.Wrapf(err, "failed to disassemble data")
		// }

		// for i, insn := range insns {
		// 	// check for start of a new function
		// 	if funcStarts != nil && isFunctionStart(funcStarts, uint64(insn.Address)) != 0 {
		// 		syms, err := m.FindAddressSymbols(uint64(insn.Address))
		// 		if len(syms) > 1 {
		// 			log.Warnf("found more than one symbol at address 0x%x, %v", insn.Address, syms)
		// 		}
		// 		if err == nil {
		// 			var symName string
		// 			if demangleFlag {
		// 				symName = doDemangle(syms[0].Name)
		// 			}
		// 			fmt.Printf("\n%s:\n", symName)
		// 		}
		// 	}

		// 	// lookup adrp/ldr or add address as a cstring or symbol name
		// 	if Verbose && (insn.Mnemonic == "ldr" || insn.Mnemonic == "add") && insns[i-1].Mnemonic == "adrp" {
		// 		if insn.Arm64.Operands != nil && len(insn.Arm64.Operands) > 1 {
		// 			if insns[i-1].Arm64.Operands != nil && len(insns[i-1].Arm64.Operands) > 1 {
		// 				adrpRegister := insns[i-1].Arm64.Operands[0].Reg
		// 				adrpImm := insns[i-1].Arm64.Operands[1].Imm
		// 				if insn.Mnemonic == "ldr" && adrpRegister == insn.Arm64.Operands[1].Mem.Base {
		// 					adrpImm += int64(insn.Arm64.Operands[1].Mem.Disp)
		// 				} else if insn.Mnemonic == "add" && adrpRegister == insn.Arm64.Operands[0].Reg {
		// 					adrpImm += insn.Arm64.Operands[2].Imm
		// 				}
		// 				// markup disassemble with label comment
		// 				syms, err := m.FindAddressSymbols(uint64(adrpImm))
		// 				if len(syms) > 1 {
		// 					log.Warnf("found more than one symbol at address 0x%x, %v", uint64(adrpImm), syms)
		// 				}
		// 				if err == nil {
		// 					var symName string
		// 					if demangleFlag {
		// 						symName = doDemangle(syms[0].Name)
		// 					}
		// 					insn.OpStr += fmt.Sprintf(" // %s", symName)
		// 				} else {
		// 					cstr, err := m.GetCString(uint64(adrpImm))
		// 					if err == nil {
		// 						insn.OpStr += fmt.Sprintf(" // %s", cstr)
		// 					}
		// 				}
		// 			}
		// 		}
		// 	}

		// 	// check if branch location is a function
		// 	if strings.HasPrefix(insn.Mnemonic, "b") && strings.HasPrefix(insn.OpStr, "#0x") {
		// 		if insn.Arm64.Operands != nil && len(insn.Arm64.Operands) > 0 {
		// 			syms, err := m.FindAddressSymbols(uint64(insn.Arm64.Operands[0].Imm))
		// 			if len(syms) > 1 {
		// 				log.Warnf("found more than one symbol at address 0x%x, %v", uint64(insn.Arm64.Operands[0].Imm), syms)
		// 			}
		// 			if err == nil {
		// 				var symName string
		// 				if demangleFlag {
		// 					symName = doDemangle(syms[0].Name)
		// 				}
		// 				insn.OpStr = symName
		// 			}
		// 		}
		// 	}

		// 	fmt.Printf("0x%x:\t%s\t\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr)
		// }

		return nil
	},
}
