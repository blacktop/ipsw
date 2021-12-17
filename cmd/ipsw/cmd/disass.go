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
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/demangle"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	// "github.com/knightsc/gapstone"
)

var (
	symbolName    string
	demangleFlag  bool
	symbolMapFile string
	symbolMap     map[uint64]string
)

func init() {
	rootCmd.AddCommand(disCmd)

	disCmd.Flags().BoolP("quiet", "q", false, "Do NOT markup analysis (Faster)")
	disCmd.Flags().StringVarP(&symbolName, "symbol", "s", "", "Function to disassemble")
	disCmd.PersistentFlags().Uint64P("vaddr", "a", 0, "Virtual address to start disassembling")
	disCmd.PersistentFlags().Uint64P("instrs", "i", 0, "Number of instructions to disassemble")
	disCmd.Flags().BoolVarP(&demangleFlag, "demangle", "d", false, "Demangle symbol names")
	disCmd.Flags().StringVarP(&symbolMapFile, "companion", "c", "", "Companion symbol map file")
	disCmd.MarkZshCompPositionalArgumentFile(1)
}

func getData(m *macho.File, startAddress *uint64, instructionCount uint64) ([]byte, error) {
	var data []byte
	var dataSize uint64
	// var fileEntry *macho.File

	// if m.FileTOC.FileHeader.Type == types.FileSet {
	// 	fileEntry, err := m.GetFileSetFileByName("kernel")
	// 	if err != nil {
	// 		return nil, errors.Wrapf(err, "macho fileset does NOT contain kernel")
	// 	}
	// 	// log.Debug(fileEntry.FileTOC.String())
	// 	if *startAddress == 0 {
	// 		for _, sec := range fileEntry.Sections {
	// 			if sec.Name == "__text" {
	// 				*startAddress = sec.Addr
	// 				return sec.Data()
	// 			}
	// 		}
	// 		return nil, fmt.Errorf("you must supply a vaddr to disassemble at")
	// 	}
	// }

	if *startAddress == 0 {
		for _, sec := range m.Sections {
			if sec.Name == "__text" {
				*startAddress = sec.Addr
				return sec.Data()
			}
		}
		return nil, fmt.Errorf("you must supply a vaddr to disassemble at")
	}

	found := false
	for _, sec := range m.Sections {
		attrs := sec.Flags.GetAttributes()
		if attrs.IsPureInstructions() || attrs.IsSomeInstructions() {
			if sec.Addr <= *startAddress && *startAddress < (sec.Addr+sec.Size) {
				found = true
				fileOffset := *startAddress - sec.Addr
				// Set number of bytes to disassemble either instrs or function size if supplied symbol
				if instructionCount > 0 {
					dataSize = 4 * instructionCount
					if dataSize > sec.Size-fileOffset {
						dataSize = sec.Size - fileOffset
					}
				} else {
					if m.FunctionStarts() != nil && *startAddress > 0 {
						if fn, err := m.GetFunctionForVMAddr(*startAddress); err != nil {
							if fn.EndAddr == 0 {
								dataSize = sec.Size - fileOffset
							} else {
								dataSize = uint64(fn.EndAddr - fn.StartAddr)
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

func lookupSymbol(m *macho.File, addr uint64) (string, bool) {

	if symName, ok := symbolMap[addr]; ok {
		if demangleFlag {
			return demangle.Do(symName, false, false), true
		}
		return symName, true
	}

	if m.Symtab == nil {
		return "", false
	}

	syms, err := m.FindAddressSymbols(addr)
	if err != nil {
		return "", false
	}

	var symName string
	if demangleFlag {
		symName = demangle.Do(syms[0].Name, false, false)
	} else {
		for _, sym := range syms {
			if len(sym.Name) > 0 {
				symName = sym.Name
			}
		}
	}

	symbolMap[addr] = symName

	return symName, true
}

func isFunctionStart(m *macho.File, addr uint64) {
	if m.FunctionStarts() != nil {
		if fn, err := m.GetFunctionForVMAddr(addr); err != nil {
			if addr == fn.StartAddr {
				if symName, ok := lookupSymbol(m, addr); ok {
					fmt.Printf("\n%s:\n", symName)
				} else {
					fmt.Printf("\nfunc_%x:\n", addr)
				}
			}
		}
	}
}

func parseObjC(m *macho.File) error {
	if m.HasObjC() {
		if cfstrs, err := m.GetCFStrings(); err == nil {
			for _, cfstr := range cfstrs {
				symbolMap[cfstr.Address] = fmt.Sprintf("%#v", cfstr.Name)
			}
		}
		if selRefs, err := m.GetObjCSelectorReferences(); err == nil {
			for off, sel := range selRefs {
				symbolMap[off] = fmt.Sprintf("sel_%s", sel.Name)
				symbolMap[sel.VMAddr] = sel.Name
			}
		}
		if methods, err := m.GetObjCMethodNames(); err == nil {
			for method, vmaddr := range methods {
				symbolMap[vmaddr] = method
			}
		}
	}
	return nil
}

func parseImports(m *macho.File) error {
	if m.HasFixups() {
		var addr uint64

		dcf, err := m.DyldChainedFixups()
		if err != nil {
			return err
		}
		if dcf.Imports != nil {
			for _, start := range dcf.Starts {
				if start.PageStarts != nil {
					binds := start.Binds()
					if len(binds) > 0 {
						for _, bind := range binds {
							fullAddend := dcf.Imports[bind.Ordinal()].Addend() + bind.Addend()
							addr = m.GetBaseAddress() + bind.Offset() + fullAddend
							symbolMap[addr] = bind.Name()
						}
					}
				}
			}
		}
	}

	return nil
}

func parseSymbolStubs(m *macho.File) error {
	for _, sec := range m.Sections {
		if sec.Flags.IsSymbolStubs() {
			data, err := sec.Data()
			if err != nil {
				return err
			}

			var instrValue uint32
			var results [1024]byte
			var prevInstr *disassemble.Instruction

			startAddr := sec.Addr
			r := bytes.NewReader(data)

			for {
				err = binary.Read(r, binary.LittleEndian, &instrValue)

				if err == io.EOF {
					break
				}

				instruction, err := disassemble.Decompose(startAddr, instrValue, &results)
				if err != nil {
					continue
				}

				if (prevInstr != nil && prevInstr.Operation == disassemble.ARM64_ADRP) &&
					(instruction.Operation == disassemble.ARM64_ADD || instruction.Operation == disassemble.ARM64_LDR) {
					adrpRegister := prevInstr.Operands[0].Registers[0]
					adrpImm := prevInstr.Operands[1].Immediate
					if instruction.Operation == disassemble.ARM64_LDR && adrpRegister == instruction.Operands[1].Registers[0] {
						adrpImm += instruction.Operands[1].Immediate
					} else if instruction.Operation == disassemble.ARM64_ADD && adrpRegister == instruction.Operands[1].Registers[0] {
						adrpImm += instruction.Operands[2].Immediate
					}
					symbolMap[prevInstr.Address] = symbolMap[adrpImm]
				}

				prevInstr = instruction
				startAddr += uint64(binary.Size(uint32(0)))
			}
		}
	}

	return nil
}

func parseGOT(m *macho.File) error {

	// authPtr := m.Section("__AUTH_CONST", "__auth_ptr")
	// data, err := authPtr.Data()
	// if err != nil {
	// 	return err
	// }
	// ptrs := make([]uint64, authPtr.Size/8)
	// if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &ptrs); err != nil {
	// 	return err
	// }
	// for _, ptr := range ptrs {
	// 	newPtr := f.SlideInfo.SlidePointer(m, ptr)
	// 	fmt.Printf("ptr: %#x\n", ptr)
	// 	fmt.Printf("newPtr: %#x, %s\n", newPtr, symbolMap[newPtr])
	// }
	for _, sec := range m.Sections {
		if sec.Flags.IsNonLazySymbolPointers() {

			data, err := sec.Data()
			if err != nil {
				return err
			}

			ptrs := make([]uint64, sec.Size/8)

			if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &ptrs); err != nil {
				return err
			}
			// imports, err := m.ImportedSymbolNames()
			// if err != nil {
			// 	return err
			// }
			// for name := range imports {
			// 	fmt.Println(name)
			// }
			for idx, ptr := range ptrs {
				gotPtr := sec.Addr + uint64(idx*8)
				// fmt.Printf("gotPtr: %#x\n", gotPtr)
				var targetValue uint64
				pointer := dyld.CacheSlidePointer3(ptr)
				if pointer.Authenticated() {
					targetValue = 0x180000000 + pointer.OffsetFromSharedCacheBase()
				} else {
					targetValue = pointer.SignExtend51()
				}
				// fmt.Printf("ptr: %#x\n", ptr)
				// fmt.Printf("newPtr: %#x, %s\n", targetValue, symbolMap[targetValue])
				// fmt.Println(lookupSymbol(m, targetValue))
				if _, ok := symbolMap[gotPtr]; ok {
					// continue
					symbolMap[gotPtr] = "__got." + symbolMap[gotPtr]
				} else {
					if _, ok := symbolMap[targetValue]; ok {
						symbolMap[gotPtr] = "__got." + symbolMap[targetValue]
					} else {
						symbolMap[gotPtr] = fmt.Sprintf("__got_ptr_%#x", targetValue)
					}
				}
			}
		}
	}

	return nil
}

// disCmd represents the dis command
var disCmd = &cobra.Command{
	Use:          "disass <MACHO>",
	Short:        "🚧 [WIP] Disassemble ARM64 binaries at address or symbol",
	Args:         cobra.MinimumNArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		var isMiddle bool
		var symAddr uint64
		var startAddr uint64

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		quiet, _ := cmd.Flags().GetBool("quiet")

		m, err := macho.Open(args[0])
		if err != nil {
			return errors.Wrapf(err, "%s appears to not be a valid MachO", args[0])
		}

		if !strings.Contains(strings.ToLower(m.FileHeader.SubCPU.String(m.CPU)), "arm64") {
			log.Errorf("can only disassemble arm64 binaries")
			return nil
		}

		if len(symbolName) > 0 {
			startAddr, err = m.FindSymbolAddress(symbolName)
			if err != nil {
				return err
			}
		} else {
			startAddr, _ = cmd.Flags().GetUint64("vaddr")
		}

		instructions, _ := cmd.Flags().GetUint64("instrs")

		data, err := getData(m, &startAddr, instructions)
		if err != nil {
			return errors.Wrapf(err, "failed to get data to disassemble")
		}

		if len(symbolMapFile) > 0 {
			a2sFile, err := os.Open(symbolMapFile)
			if err != nil {
				return errors.Wrapf(err, "failed to open companion file")
			}
			// Decoding the serialized data
			err = gob.NewDecoder(a2sFile).Decode(&symbolMap)
			if err != nil {
				return err
			}
		} else {
			symbolMap = make(map[uint64]string)
		}

		err = parseImports(m)
		if err != nil {
			return errors.Wrapf(err, "failed to parse imports")
		}

		err = parseObjC(m)
		if err != nil {
			return errors.Wrapf(err, "failed to parse objc runtime")
		}

		err = parseSymbolStubs(m)
		if err != nil {
			return errors.Wrapf(err, "failed to parse symbol stubs")
		}

		err = parseGOT(m)
		if err != nil {
			return errors.Wrapf(err, "failed to parse got(s)")
		}

		var instrStr string
		var instrValue uint32
		var results [1024]byte
		var prevInstr *disassemble.Instruction

		r := bytes.NewReader(data)

		for {
			err = binary.Read(r, binary.LittleEndian, &instrValue)

			if err == io.EOF {
				break
			}

			instruction, err := disassemble.Decompose(startAddr, instrValue, &results)
			if err != nil {
				fmt.Printf("%#08x:  %s\t.long\t%#x ; (%s)\n", uint64(startAddr), disassemble.GetOpCodeByteString(instrValue), instrValue, err.Error())
				break
			}

			instrStr = instruction.String()

			// opStr := i.Instruction.OpStr()

			// check for start of a new function
			isFunctionStart(m, instruction.Address)

			if !quiet {
				// if triage.IsBranchLocation(instruction.Address) {
				// 	fmt.Printf("%#08x:  ; loc_%x\n", instruction.Address, instruction.Address)
				// }

				if instruction.Operation == disassemble.ARM64_MRS || instruction.Operation == disassemble.ARM64_MSR {
					var ops []string
					replaced := false
					for _, op := range instruction.Operands {
						if op.Class == disassemble.REG {
							ops = append(ops, op.Registers[0].String())
						} else if op.Class == disassemble.IMPLEMENTATION_SPECIFIC {
							sysRegFix := op.ImplSpec.GetSysReg().String()
							if len(sysRegFix) > 0 {
								ops = append(ops, sysRegFix)
								replaced = true
							}
						}
						if replaced {
							instrStr = fmt.Sprintf("%s\t%s", instruction.Operation, strings.Join(ops, ", "))
						}
					}
				}

				if instruction.Encoding == disassemble.ENC_BL_ONLY_BRANCH_IMM || instruction.Encoding == disassemble.ENC_B_ONLY_BRANCH_IMM {
					if name, ok := lookupSymbol(m, uint64(instruction.Operands[0].Immediate)); ok {
						instrStr = fmt.Sprintf("%s\t%s", instruction.Operation, name)
					}
				}

				if instruction.Encoding == disassemble.ENC_CBZ_64_COMPBRANCH {
					if name, ok := lookupSymbol(m, uint64(instruction.Operands[1].Immediate)); ok {
						instrStr += fmt.Sprintf(" ; %s", name)
					}
				}

				if instruction.Operation == disassemble.ARM64_ADR {
					adrImm := instruction.Operands[1].Immediate
					if name, ok := lookupSymbol(m, uint64(adrImm)); ok {
						instrStr += fmt.Sprintf(" ; %s", name)
					} else if cstr, err := m.GetCString(adrImm); err == nil {
						if utils.IsASCII(cstr) {
							if len(cstr) > 200 {
								instrStr += fmt.Sprintf(" ; %#v...", cstr[:200])
							} else if len(cstr) > 1 {
								instrStr += fmt.Sprintf(" ; %#v", cstr)
							}
						}
					}
				}

				if (prevInstr != nil && prevInstr.Operation == disassemble.ARM64_ADRP) && (instruction.Operation == disassemble.ARM64_ADD || instruction.Operation == disassemble.ARM64_LDR) {
					adrpRegister := prevInstr.Operands[0].Registers[0]
					adrpImm := prevInstr.Operands[1].Immediate
					if instruction.Operation == disassemble.ARM64_LDR && adrpRegister == instruction.Operands[1].Registers[0] {
						adrpImm += instruction.Operands[1].Immediate
					} else if instruction.Operation == disassemble.ARM64_ADD && adrpRegister == instruction.Operands[1].Registers[0] {
						adrpImm += instruction.Operands[2].Immediate
					}
					if name, ok := lookupSymbol(m, uint64(adrpImm)); ok {
						instrStr += fmt.Sprintf(" ; %s", name)
					} else if cstr, err := m.GetCString(adrpImm); err == nil {
						if utils.IsASCII(cstr) {
							if len(cstr) > 200 {
								instrStr += fmt.Sprintf(" ; %#v...", cstr[:200])
							} else if len(cstr) > 1 {
								instrStr += fmt.Sprintf(" ; %#v", cstr)
							}
						}
					}
				}
			}

			if isMiddle && startVMAddr == symAddr {
				fmt.Printf("👉%08x:  %s\t%s\n", uint64(startAddr), disassemble.GetOpCodeByteString(instrValue), instrStr)
			} else {
				fmt.Printf("%#08x:  %s\t%s\n", uint64(startAddr), disassemble.GetOpCodeByteString(instrValue), instrStr)
			}

			prevInstr = instruction
			startAddr += uint64(binary.Size(uint32(0)))
		}

		return nil
	},
}
