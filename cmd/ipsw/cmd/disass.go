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
	disCmd.PersistentFlags().Uint64P("instrs", "i", 0, "Number of instructions to disassemble")
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

func getFunctionSize(m *macho.File, addr uint64) int64 {
	if m.FunctionStarts() != nil {
		starts := m.FunctionStarts()
		i := sort.Search(len(starts), func(i int) bool { return starts[i] >= addr })
		if i+1 == len(starts) && starts[i] == addr {
			return -1
		} else if i < len(starts) && starts[i] == addr {
			return int64(starts[i+1] - addr)
		}
	}
	return 0
}

func getData(m *macho.File, startAddress, instructionCount uint64) ([]byte, error) {
	var data []byte
	var dataSize uint64

	found := false
	for _, sec := range m.Sections {
		attrs := sec.Flags.GetAttributes()
		if attrs.IsPureInstructions() || attrs.IsSomeInstructions() {
			if sec.Addr <= startAddress && startAddress < (sec.Addr+sec.Size) {
				found = true

				fileOffset := startAddress - sec.Addr

				// Set number of bytes to disassemble either instrs or function size if supplied symbol
				if instructionCount > 0 {
					dataSize = 4 * instructionCount
					if dataSize > sec.Size-fileOffset {
						dataSize = sec.Size - fileOffset
					}
				} else {
					if m.FunctionStarts() != nil && startAddress > 0 {
						funcSize := getFunctionSize(m, startAddress)
						if funcSize != 0 {
							if funcSize == -1 { // last function in starts, size is start to end of section
								dataSize = sec.Size - fileOffset
							} else {
								dataSize = uint64(funcSize)
							}
						} else {
							dataSize = sec.Size - fileOffset // not a function start (disassemble from start address to end of section)
						}
					}
				}

				data = make([]byte, dataSize)

				_, err := sec.ReadAt(data, int64(fileOffset))
				if err != nil {
					return nil, err
				}

				break
			}
		}
	}

	if !found {
		return nil, fmt.Errorf("supplied vaddr not found in any executable section")
	}

	return data, nil
}

func lookupSymbol(m *macho.File, addr uint64) string {
	syms, err := m.FindAddressSymbols(addr)
	if err != nil {
		return ""
	}

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

	return symName
}

func isFunctionStart(m *macho.File, addr uint64) {
	if m.FunctionStarts() != nil {
		if getFunctionSize(m, addr) != 0 {
			symName := lookupSymbol(m, addr)
			if len(symName) > 0 {
				fmt.Printf("\n%s:\n", symName)
			} else {
				fmt.Printf("\nfunc_%x:\n", addr)
			}
		}
	}
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

		var startAddr uint64

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		m, err := macho.Open(args[0])
		if err != nil {
			return errors.Wrapf(err, "%s appears to not be a valid MachO", args[0])
		}

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

		instructions, _ := cmd.Flags().GetUint64("instrs")

		data, err := getData(m, startAddr, instructions)
		if err != nil {
			return errors.Wrapf(err, "failed to get data to disassemble")
		}

		var prevInstruction arm64.Instruction

		for i := range arm64.Disassemble(bytes.NewReader(data), arm64.Options{StartAddress: int64(startAddr)}) {
			opStr := i.Instruction.OpStr()

			// check for start of a new function
			isFunctionStart(m, i.Instruction.Address())

			// lookup adrp/ldr or add address as a cstring or symbol name
			operation := i.Instruction.Operation().String()
			if (operation == "ldr" || operation == "add") && prevInstruction.Operation().String() == "adrp" {
				operands := i.Instruction.Operands()
				if operands != nil && prevInstruction.Operands() != nil {
					adrpRegister := prevInstruction.Operands()[0].Reg[0]
					adrpImm := prevInstruction.Operands()[1].Immediate
					if operation == "ldr" && adrpRegister == operands[1].Reg[0] {
						adrpImm += operands[1].Immediate
					} else if operation == "add" && adrpRegister == operands[0].Reg[0] {
						adrpImm += operands[2].Immediate
					}
					// markup disassemble with label comment
					symName := lookupSymbol(m, adrpImm)
					if len(symName) > 0 {
						opStr += fmt.Sprintf(" // %s", symName)
					} else {
						cstr, err := m.GetCString(adrpImm)
						if err == nil {
							opStr += fmt.Sprintf(" // %s", cstr)
						}
					}
				}

			} else if i.Instruction.Group() == arm64.GROUP_BRANCH_EXCEPTION_SYSTEM { // check if branch location is a function
				operands := i.Instruction.Operands()
				if operands != nil && operands[0].OpClass == arm64.LABEL {
					symName := lookupSymbol(m, operands[0].Immediate)
					if len(symName) > 0 {
						opStr = fmt.Sprintf("\t%s", symName)
					}
				}
			}

			fmt.Printf("%#08x:  %s\t%s%s%s\n", i.Instruction.Address(), i.Instruction.OpCodes(), i.Instruction.Operation(), pad(10-len(i.Instruction.Operation().String())), opStr)

			prevInstruction = *i.Instruction
		}

		return nil
	},
}
