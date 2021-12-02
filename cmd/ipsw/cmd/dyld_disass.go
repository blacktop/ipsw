/*
Copyright © 2021 blacktop

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
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-arm64"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	dyldCmd.AddCommand(dyldDisassCmd)

	dyldDisassCmd.Flags().Uint64P("slide", "", 0, "dyld_shared_cache slide to remove from --vaddr")
	dyldDisassCmd.Flags().StringP("symbol", "s", "", "Function to disassemble")
	dyldDisassCmd.Flags().Uint64P("vaddr", "a", 0, "Virtual address to start disassembling")
	dyldDisassCmd.Flags().Uint64P("count", "c", 0, "Number of instructions to disassemble")
	dyldDisassCmd.Flags().BoolVarP(&demangleFlag, "demangle", "d", false, "Demangle symbol names")
	dyldDisassCmd.Flags().StringP("cache", "", "", "Path to addr to sym cache file (speeds up analysis)")
	dyldDisassCmd.Flags().StringP("image", "i", "", "dylib image to search")

	symaddrCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

// disassCmd represents the disass command
var dyldDisassCmd = &cobra.Command{
	Use:           "disass <dyld_shared_cache>",
	Short:         "🚧 [WIP] Disassemble dyld_shared_cache symbol/vaddr in an image",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  false,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		var data []byte
		var isMiddle bool
		var symAddr uint64
		var startAddr uint64
		var image *dyld.CacheImage
		var dFunc *types.Function

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		imageName, _ := cmd.Flags().GetString("image")
		instructions, _ := cmd.Flags().GetUint64("count")
		startVMAddr, _ := cmd.Flags().GetUint64("vaddr")
		symbolName, _ := cmd.Flags().GetString("symbol")
		cacheFile, _ := cmd.Flags().GetString("cache")
		slide, _ := cmd.Flags().GetUint64("slide")

		if len(symbolName) > 0 && startVMAddr != 0 {
			return fmt.Errorf("you can only use --symbol OR --vaddr (not both)")
		} else if len(symbolName) == 0 && startVMAddr == 0 {
			return fmt.Errorf("you must supply a --symbol OR --vaddr to disassemble")
		}

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

		if !f.IsArm64() {
			log.Errorf("can only disassemble arm64 caches")
			return nil
		}

		if len(symbolName) > 0 {
			if len(imageName) == 0 {
				if len(cacheFile) == 0 {
					cacheFile = dscPath + ".a2s"
				}
				if err := f.OpenOrCreateA2SCache(cacheFile); err != nil {
					return err
				}
			} else {
				utils.Indent(log.Warn, 2)("parsing public symbols...")
				if err := f.GetAllExportedSymbolsForImage(image, false); err != nil {
					log.Error("failed to parse exported symbols")
				}
				utils.Indent(log.Warn, 2)("parsing private symbols...")
				if err := f.GetLocalSymbolsForImage(image); err != nil {
					if errors.Is(err, dyld.ErrNoLocals) {
						utils.Indent(log.Warn, 2)(err.Error())
					} else if err != nil {
						return err
					}
				}
			}

			log.Info("Locating symbol: " + symbolName)
			symAddr, image, err = f.GetSymbolAddress(symbolName, imageName)
			if err != nil {
				return err
			}

		} else { // startVMAddr > 0
			if slide > 0 {
				startVMAddr = startVMAddr - slide
			}
			symAddr = startVMAddr
		}

		startAddr = symAddr

		if image == nil {
			image, err = f.GetImageContainingTextAddr(symAddr)
			if err != nil {
				return err
			}
		}

		log.WithFields(log.Fields{"dylib": image.Name}).Info("Found symbol")

		m, err := image.GetMacho()
		if err != nil {
			return err
		}
		defer m.Close()

		/*
		 * Read in data to disassemble
		 */
		if instructions > 0 {
			uuid, off, err := f.GetOffset(symAddr)
			if err != nil {
				return err
			}
			data, err = f.ReadBytesForUUID(uuid, int64(off), instructions*4)
			if err != nil {
				return err
			}
		} else {
			if fn, err := m.GetFunctionForVMAddr(symAddr); err == nil {
				dFunc = &fn
				uuid, soff, err := f.GetOffset(fn.StartAddr)
				if err != nil {
					return err
				}
				data, err = f.ReadBytesForUUID(uuid, int64(soff), uint64(fn.EndAddr-fn.StartAddr))
				if err != nil {
					return err
				}
				if symAddr != fn.StartAddr {
					isMiddle = true
					startAddr = fn.StartAddr
				}
			}
		}

		if data == nil {
			log.Fatal("failed to disassemble")
		}

		/*
		 * Load symbols from the target sym/addr's image
		 */
		// if f.LocalSymbolsOffset == 0 {
		// 	utils.Indent(log.Warn, 2)("parsing symbol table...")
		// 	for _, sym := range m.Symtab.Syms {
		// 		if sym.Value != 0 {
		// 			f.AddressToSymbol[sym.Value] = sym.Name
		// 		}
		// 	}
		// }
		if len(symbolName) == 0 {
			utils.Indent(log.Warn, 2)("parsing public symbols...")
			if err := f.GetAllExportedSymbolsForImage(image, false); err != nil {
				log.Error("failed to parse exported symbols")
			}
			utils.Indent(log.Warn, 2)("parsing private symbols...")
			if err := f.GetLocalSymbolsForImage(image); err != nil {
				if errors.Is(err, dyld.ErrNoLocals) {
					utils.Indent(log.Warn, 2)(err.Error())
				} else if err != nil {
					return err
				}
			}
		}

		//***********************
		//* First pass ANALYSIS *
		//***********************
		triage, err := f.FirstPassTriage(m, dFunc, bytes.NewReader(data), arm64.Options{StartAddress: int64(startAddr)}, true)
		if err == nil {
			for _, img := range triage.Dylibs {
				if err := f.AnalyzeImage(img); err != nil {
					return err
				}
			}
		} else {
			log.Errorf("first pass triage failed: %v", err)
		}

		/*
		 * Load symbols from all of the dylibs loaded by the target sym/addr's image
		 */
		// if len(symbolName) == 0 {
		// 	if !image.Analysis.State.IsDepsDone() {
		// 		utils.Indent(log.Warn, 2)("parsing imported dylib symbols...")
		// 		if err := f.ImageDependencies(image.Name); err == nil {
		// 			for _, dep := range image.Analysis.Dependencies {
		// 				if err := f.GetAllExportedSymbolsForImage(dep, false); err != nil {
		// 					log.Errorf("failed to parse exported symbols for %s", dep)
		// 				}
		// 				if err := f.GetLocalSymbolsForImage(dep); err != nil {
		// 					log.Errorf("failed to parse local symbols for %s", dep)
		// 				}
		// 				dM, err := f.Image(dep).GetMacho()
		// 				if err != nil {
		// 					return err
		// 				}
		// 				// TODO: create a dep tree and analyze them all (lazily if possible)
		// 				fmt.Println(dep)
		// 				if err := f.ParseSymbolStubs(dM); err != nil {
		// 					return err
		// 				}
		// 				dM.Close()
		// 			}
		// 		}
		// 		image.Analysis.State.SetDeps(true)
		// 	}
		// }

		if m.HasObjC() {
			log.Info("Parsing ObjC runtime structures...")
			if err := f.CFStringsForImage(image.Name); err != nil {
				return errors.Wrapf(err, "failed to parse objc cfstrings")
			}
			if err := f.MethodsForImage(image.Name); err != nil {
				return errors.Wrapf(err, "failed to parse objc methods")
			}
			if strings.Contains(image.Name, "libobjc.A.dylib") {
				_, err = f.GetAllSelectors(false)
			} else {
				err = f.SelectorsForImage(image.Name)
			}
			if err != nil {
				return errors.Wrapf(err, "failed to parse objc selectors")
			}
			if err := f.ClassesForImage(image.Name); err != nil {
				return errors.Wrapf(err, "failed to parse objc classes")
			}
			if err := f.ProtocolsForImage(image.Name); err != nil {
				return errors.Wrapf(err, "failed to parse objc protocols")
			}
		}

		if err := f.AnalyzeImage(image); err != nil {
			return err
		}

		//***************
		//* DISASSEMBLE *
		//***************

		var prevInstruction arm64.Instruction

		for i := range arm64.Disassemble(bytes.NewReader(data), arm64.Options{StartAddress: int64(startAddr)}) {

			if i.Error != nil {
				fmt.Println(i.StrRepr)
				continue
			}

			opStr := i.Instruction.OpStr()

			// check for start of a new function
			if yes, fname := f.IsFunctionStart(m.GetFunctions(), i.Instruction.Address(), demangleFlag); yes {
				if len(fname) > 0 {
					fmt.Printf("\n%s:\n", fname)
				} else {
					fmt.Printf("\nfunc_%x:\n", i.Instruction.Address())
				}
			}

			if triage.IsBranchLocation(i.Instruction.Address()) {
				fmt.Printf("%#08x:  ; loc_%x\n", i.Instruction.Address(), i.Instruction.Address())
			}

			// if ok, imm := triage.HasLoc(i.Instruction.Address()); ok {
			// 	if detail, ok := triage.Details[imm]; ok {
			// 		if triage.IsData(imm) {
			// 			opStr += fmt.Sprintf(" ; %s", detail)
			// 		} else {
			// 			opStr += fmt.Sprintf(" ; %s", detail)
			// 		}
			// 	}
			// }

			// lookup adrp/ldr or add address as a cstring or symbol name
			operation := i.Instruction.Operation().String()
			if (operation == "ldr" || operation == "add") && prevInstruction.Operation().String() == "adrp" {
				operands := i.Instruction.Operands()
				if operands != nil && prevInstruction.Operands() != nil {
					adrpRegister := prevInstruction.Operands()[0].Reg[0]
					adrpImm := prevInstruction.Operands()[1].Immediate
					if operation == "ldr" && adrpRegister == operands[1].Reg[0] {
						adrpImm += operands[1].Immediate
					} else if operation == "add" && adrpRegister == operands[1].Reg[0] {
						adrpImm += operands[2].Immediate
					}
					// markup disassemble with label comment
					symName := f.FindSymbol(adrpImm, demangleFlag)
					if len(symName) > 0 {
						opStr += fmt.Sprintf(" ; %s", symName)
					} else {
						cstr, err := f.IsCString(m, adrpImm)
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
				if operands := i.Instruction.Operands(); operands != nil {
					for _, operand := range operands {
						if operand.OpClass == arm64.LABEL {
							symName := f.FindSymbol(operand.Immediate, demangleFlag)
							if len(symName) > 0 {
								opStr = fmt.Sprintf("\t%s", symName)
							} else {
								if dFunc != nil {
									if operand.Immediate >= dFunc.StartAddr && operand.Immediate < dFunc.EndAddr {
										direction := ""
										delta := int(operand.Immediate) - int(i.Instruction.Address())
										if delta > 0 {
											direction = fmt.Sprintf(" ; ⤵ %#x", delta)
										} else if delta == 0 {
											direction = " ; ∞ loop"
										} else {
											direction = fmt.Sprintf(" ; ⤴ %#x", delta)
										}
										opStr = strings.Replace(opStr, fmt.Sprintf("#%#x", operand.Immediate), fmt.Sprintf("loc_%x%s", operand.Immediate, direction), 1)
									}
								}
							}
						}
					}
				}

			} else if i.Instruction.Group() == arm64.GROUP_DATA_PROCESSING_IMM || i.Instruction.Group() == arm64.GROUP_LOAD_STORE {
				operation := i.Instruction.Operation()
				if operation == arm64.ARM64_LDR || operation == arm64.ARM64_ADR {
					operands := i.Instruction.Operands()
					if operands[1].OpClass == arm64.LABEL {
						symName := f.FindSymbol(operands[1].Immediate, demangleFlag)
						if len(symName) > 0 {
							opStr += fmt.Sprintf(" ; %s", symName)
						} else {
							if dFunc != nil {
								if operands[1].Immediate >= dFunc.StartAddr && operands[1].Immediate < dFunc.EndAddr {
									opStr = fmt.Sprintf("\tloc_%x", operands[1].Immediate)
								}
							}
						}
					}
				}
			}

			if isMiddle && i.Instruction.Address() == symAddr {
				fmt.Printf("👉%08x:  %s\t%-10v%s\n", i.Instruction.Address(), i.Instruction.OpCodes(), i.Instruction.Operation(), opStr)
			} else {
				fmt.Printf("%#08x:  %s\t%-10v%s\n", i.Instruction.Address(), i.Instruction.OpCodes(), i.Instruction.Operation(), opStr)
			}

			prevInstruction = *i.Instruction
		}

		return nil
	},
}
