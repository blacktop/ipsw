/*
Copyright © 2020 blacktop

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
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/apex/log"
	"github.com/blacktop/go-arm64"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	dyldCmd.AddCommand(dyldDisassCmd)

	// dyldDisassCmd.Flags().StringP("symbol", "s", "", "Function to disassemble")
	// dyldDisassCmd.Flags().Uint64P("vaddr", "a", 0, "Virtual address to start disassembling")
	dyldDisassCmd.Flags().Uint64P("count", "c", 0, "Number of instructions to disassemble")
	dyldDisassCmd.Flags().BoolVarP(&demangleFlag, "demangle", "d", false, "Demandle symbol names")
	dyldDisassCmd.Flags().StringP("sym-file", "s", "", "Companion symbol map file")
	dyldDisassCmd.Flags().StringP("image", "i", "", "dylib image to search")

	symaddrCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

func functionSize(starts []uint64, addr uint64) int64 {
	i := sort.Search(len(starts), func(i int) bool { return starts[i] >= addr })
	if i+1 == len(starts) && starts[i] == addr {
		return -1
	} else if i < len(starts) && starts[i] == addr {
		return int64(starts[i+1] - addr)
	}
	return 0
}

func functionStart(starts []uint64, addr uint64) {
	if functionSize(starts, addr) != 0 {
		if symName, ok := symbolMap[addr]; ok {
			fmt.Printf("\n%s:\n", symName)
		} else {
			fmt.Printf("\nfunc_%x:\n", addr)
		}
	}
}

func findSymbol(addr uint64) string {

	if symName, ok := symbolMap[addr]; ok {
		if demangleFlag {
			return doDemangle(symName)
		}
		return symName
	}

	return ""
}

// disassCmd represents the disass command
var dyldDisassCmd = &cobra.Command{
	Use:    "disass",
	Short:  "🚧 [WIP] Disassemble dyld_shared_cache symbol in an image",
	Hidden: true,
	Args:   cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {

		var image *dyld.CacheImage
		var symAddr uint64

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		imageName, _ := cmd.Flags().GetString("image")
		instructions, _ := cmd.Flags().GetUint64("count")

		// symbolName, _ := cmd.Flags().GetString("symbol")
		// doDemangle, _ := cmd.Flags().GetBool("demangle")

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

		if _, err := os.Stat(dscPath + ".a2s"); os.IsNotExist(err) {
			log.Warn("parsing public symbols...")
			err = f.GetAllExportedSymbols(false)
			if err != nil {
				return err
			}
			log.Warn("parsing private symbols...")
			err = f.ParseLocalSyms()
			if err != nil {
				return err
			}

			// save lookup map to disk to speed up subsequent requests
			f.SaveAddrToSymMap(dscPath + ".a2s")

			return nil
		}

		a2sFile, err := os.Open(dscPath + ".a2s")
		if err != nil {
			return err
		}
		// Decoding the serialized data
		err = gob.NewDecoder(a2sFile).Decode(&symbolMap)
		if err != nil {
			return err
		}

		if len(args) > 1 {
			found := false
			if len(imageName) > 0 { // Search for symbol inside dylib
				image = f.Image(imageName)
				if sym, _ := f.FindExportedSymbolInImage(imageName, args[1]); sym != nil {
					symAddr = sym.Address
					found = true
				} else if lSym, _ := f.FindLocalSymbolInImage(args[1], imageName); lSym != nil {
					symAddr = lSym.Value
					found = true
				}
			} else {
				// Search ALL dylibs for a symbol
				for _, img := range f.Images {
					if sym, _ := f.FindExportedSymbolInImage(img.Name, args[1]); sym != nil {
						image = img
						symAddr = sym.Address
						found = true
						break
					}
				}
				if !found {
					if lSym, _ := f.FindLocalSymbol(args[1]); lSym != nil {
						symAddr = lSym.Value
					} else {
						return fmt.Errorf("symbol %s not found", args[1])
					}
				}

				m, err := image.GetPartialMacho()
				if err != nil {
					return err
				}

				var starts []uint64
				if fs := m.FunctionStarts(); fs != nil {
					data, err := f.ReadBytes(int64(fs.Offset), uint64(fs.Size))
					if err != nil {
						return err
					}
					starts = m.FunctionStartAddrs(data...)
				}

				// fmt.Println(m.FileTOC.String())

				fmt.Println(image.Name)
				// if image != nil {
				// 	fmt.Println(image.Name)
				// } else {
				// 	if image, err := f.GetImageContainingTextAddr(symAddr); err == nil {
				// 		fmt.Println(image.Name)
				// 	}
				// }

				off, _ := f.GetOffset(symAddr)
				var data []byte
				if instructions > 0 {
					data, err = f.ReadBytes(int64(off), instructions*4)
					if err != nil {
						return err
					}
				} else {
					data, err = f.ReadBytes(int64(off), uint64(functionSize(starts, symAddr)))
					if err != nil {
						return err
					}
				}

				// err = parseImports(m)
				// if err != nil {
				// 	return errors.Wrapf(err, "failed to parse imports")
				// }

				// err = parseObjC(m)
				// if err != nil {
				// 	return errors.Wrapf(err, "failed to parse objc runtime")
				// }

				// err = parseSymbolStubs(m)
				// if err != nil {
				// 	return errors.Wrapf(err, "failed to parse symbol stubs")
				// }

				// err = parseGOT(m)
				// if err != nil {
				// 	return errors.Wrapf(err, "failed to parse got(s)")
				// }

				var prevInstruction arm64.Instruction

				for i := range arm64.Disassemble(bytes.NewReader(data), arm64.Options{StartAddress: int64(symAddr)}) {

					if i.Error != nil {
						fmt.Println(i.StrRepr)
						continue
					}

					opStr := i.Instruction.OpStr()

					// check for start of a new function
					functionStart(starts, i.Instruction.Address())

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
							symName := findSymbol(adrpImm)
							if len(symName) > 0 {
								opStr += fmt.Sprintf(" ; %s", symName)
							} else {
								cstr, err := f.GetCString(adrpImm)
								if err == nil {
									if len(cstr) > 200 {
										opStr += fmt.Sprintf(" ; %#v...", cstr[:200])
									} else {
										opStr += fmt.Sprintf(" ; %#v", cstr)
									}
								}
							}
						}

					} else if i.Instruction.Group() == arm64.GROUP_BRANCH_EXCEPTION_SYSTEM { // check if branch location is a function
						operands := i.Instruction.Operands()
						if operands != nil && operands[0].OpClass == arm64.LABEL {
							symName := findSymbol(operands[0].Immediate)
							if len(symName) > 0 {
								opStr = fmt.Sprintf("\t%s", symName)
							}
						}
					} else if i.Instruction.Group() == arm64.GROUP_DATA_PROCESSING_IMM || i.Instruction.Group() == arm64.GROUP_LOAD_STORE {
						operation := i.Instruction.Operation()
						if operation == arm64.ARM64_LDR || operation == arm64.ARM64_ADR {
							operands := i.Instruction.Operands()
							if operands[1].OpClass == arm64.LABEL {
								symName := findSymbol(operands[1].Immediate)
								if len(symName) > 0 {
									opStr += fmt.Sprintf(" ; %s", symName)
								}
							}
						}
					}

					fmt.Printf("%#08x:  %s\t%s%s%s\n", i.Instruction.Address(), i.Instruction.OpCodes(), i.Instruction.Operation(), pad(10-len(i.Instruction.Operation().String())), opStr)

					prevInstruction = *i.Instruction
				}
			}
		} else {
			return fmt.Errorf("you must supply a cache and a symbol to disassemble")
		}

		return nil
	},
}
