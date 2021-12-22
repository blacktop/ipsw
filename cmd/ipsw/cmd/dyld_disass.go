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
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/disass"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	dyldCmd.AddCommand(dyldDisassCmd)

	dyldDisassCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	dyldDisassCmd.Flags().BoolP("all", "", false, "Disassemble all functions")
	dyldDisassCmd.Flags().BoolP("quiet", "q", false, "Do NOT markup analysis (Faster)")
	dyldDisassCmd.Flags().Uint64("slide", 0, "dyld_shared_cache slide to remove from --vaddr")
	dyldDisassCmd.Flags().StringP("symbol", "s", "", "Function to disassemble")
	dyldDisassCmd.Flags().Uint64P("vaddr", "a", 0, "Virtual address to start disassembling")
	dyldDisassCmd.Flags().Uint64P("count", "c", 0, "Number of instructions to disassemble")
	dyldDisassCmd.Flags().BoolVarP(&demangleFlag, "demangle", "d", false, "Demangle symbol names")
	dyldDisassCmd.Flags().String("cache", "", "Path to .a2s addr to sym cache file (speeds up analysis)")
	dyldDisassCmd.Flags().StringP("image", "i", "", "dylib image to search")

	symaddrCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

// disassCmd represents the disass command
var dyldDisassCmd = &cobra.Command{
	Use:           "disass <dyld_shared_cache>",
	Short:         "Disassemble dyld_shared_cache symbol/vaddr in an image",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  false,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		var data []byte
		var isMiddle bool
		var image *dyld.CacheImage

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		imageName, _ := cmd.Flags().GetString("image")
		instructions, _ := cmd.Flags().GetUint64("count")
		startAddr, _ := cmd.Flags().GetUint64("vaddr")
		symbolName, _ := cmd.Flags().GetString("symbol")
		cacheFile, _ := cmd.Flags().GetString("cache")
		slide, _ := cmd.Flags().GetUint64("slide")
		asJSON, _ := cmd.Flags().GetBool("json")
		// allFuncs, _ := cmd.Flags().GetBool("all")
		quiet, _ := cmd.Flags().GetBool("quiet")

		if len(symbolName) > 0 && startAddr != 0 {
			return fmt.Errorf("you can only use --symbol OR --vaddr (not both)")
		} else if len(symbolName) == 0 && startAddr == 0 {
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
				image, err = f.Image(imageName)
				if err != nil {
					return fmt.Errorf("image not in %s: %v", dscPath, err)
				}
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
			startAddr, image, err = f.GetSymbolAddress(symbolName, imageName)
			if err != nil {
				return err
			}

		} else { // startAddr > 0
			if slide > 0 {
				startAddr = startAddr - slide
			}
		}

		if image == nil {
			image, err = f.GetImageContainingTextAddr(startAddr)
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
			if err := f.ParseObjcForImage(image.Name); err != nil {
				return fmt.Errorf("failed to parse objc data for image %s: %v", image.Name, err)
			}
		}

		if err := image.Analyze(); err != nil {
			return err
		}

		/*
		 * Read in data to disassemble
		 */
		if instructions > 0 {
			uuid, off, err := f.GetOffset(startAddr)
			if err != nil {
				return err
			}
			data, err = f.ReadBytesForUUID(uuid, int64(off), instructions*4)
			if err != nil {
				return err
			}
		} else {
			if fn, err := m.GetFunctionForVMAddr(startAddr); err == nil {
				uuid, soff, err := f.GetOffset(fn.StartAddr)
				if err != nil {
					return err
				}
				data, err = f.ReadBytesForUUID(uuid, int64(soff), uint64(fn.EndAddr-fn.StartAddr))
				if err != nil {
					return err
				}
				if startAddr != fn.StartAddr {
					isMiddle = true
					startAddr = fn.StartAddr
				}
			}
		}

		if data == nil {
			log.Fatal("failed to disassemble")
		}

		//***************
		//* DISASSEMBLE *
		//***************
		engine := disass.NewDyldDisass(f, &disass.Config{
			Image:        image.Name,
			Data:         data,
			StartAddress: startAddr,
			Middle:       isMiddle,
			AsJSON:       asJSON,
			Demangle:     demangleFlag,
			Quite:        quiet,
		})

		//***********************
		//* First pass ANALYSIS *
		//***********************
		if err := engine.Triage(); err != nil {
			return fmt.Errorf("first pass triage failed: %v", err)
		}
		for _, img := range engine.Dylibs() {
			if err := img.Analyze(); err != nil {
				return err
			}
		}

		disass.Disassemble(engine)

		// var instrStr string
		// var instrValue uint32
		// var results [1024]byte
		// var prevInstr *disassemble.Instruction

		// r := bytes.NewReader(data)

		// for {
		// 	err = binary.Read(r, binary.LittleEndian, &instrValue)

		// 	if err == io.EOF {
		// 		break
		// 	}

		// 	instruction, err := disassemble.Decompose(startAddr, instrValue, &results)
		// 	if err != nil {
		// 		fmt.Printf("%#08x:  %s\t.long\t%#x ; (%s)\n", uint64(startAddr), disassemble.GetOpCodeByteString(instrValue), instrValue, err.Error())
		// 		break
		// 	}

		// 	instrStr = instruction.String()

		// 	// check for start of a new function
		// 	if yes, fname := f.IsFunctionStart(m.GetFunctions(), instruction.Address, demangleFlag); yes {
		// 		if len(fname) > 0 {
		// 			fmt.Printf("\n%s:\n", fname)
		// 		} else {
		// 			fmt.Printf("\nfunc_%x:\n", instruction.Address)
		// 		}
		// 	}

		// 	// if ok, imm := triage.HasLoc(instruction.Address); ok {
		// 	// 	if detail, ok := triage.Details[imm]; ok {
		// 	// 		if triage.IsData(imm) {
		// 	// 			opStr += fmt.Sprintf(" ; %s", detail)
		// 	// 		} else {
		// 	// 			opStr += fmt.Sprintf(" ; %s", detail)
		// 	// 		}
		// 	// 	}
		// 	// }

		// 	if !quiet {
		// 		if triage.IsBranchLocation(instruction.Address) {
		// 			fmt.Printf("%#08x:  ; loc_%x\n", instruction.Address, instruction.Address)
		// 		}

		// 		if instruction.Operation == disassemble.ARM64_MRS || instruction.Operation == disassemble.ARM64_MSR {
		// 			var ops []string
		// 			replaced := false
		// 			for _, op := range instruction.Operands {
		// 				if op.Class == disassemble.REG {
		// 					ops = append(ops, op.Registers[0].String())
		// 				} else if op.Class == disassemble.IMPLEMENTATION_SPECIFIC {
		// 					sysRegFix := op.ImplSpec.GetSysReg().String()
		// 					if len(sysRegFix) > 0 {
		// 						ops = append(ops, sysRegFix)
		// 						replaced = true
		// 					}
		// 				}
		// 				if replaced {
		// 					instrStr = fmt.Sprintf("%s\t%s", instruction.Operation, strings.Join(ops, ", "))
		// 				}
		// 			}
		// 		}

		// 		if instruction.Encoding == disassemble.ENC_BL_ONLY_BRANCH_IMM || instruction.Encoding == disassemble.ENC_B_ONLY_BRANCH_IMM {
		// 			if name, ok := f.AddressToSymbol[uint64(instruction.Operands[0].Immediate)]; ok {
		// 				instrStr = fmt.Sprintf("%s\t%s", instruction.Operation, name)
		// 			}
		// 		}

		// 		if instruction.Encoding == disassemble.ENC_CBZ_64_COMPBRANCH {
		// 			if name, ok := f.AddressToSymbol[uint64(instruction.Operands[1].Immediate)]; ok {
		// 				instrStr += fmt.Sprintf(" ; %s", name)
		// 			}
		// 		}

		// 		if instruction.Operation == disassemble.ARM64_ADR {
		// 			adrImm := instruction.Operands[1].Immediate
		// 			if name, ok := f.AddressToSymbol[uint64(adrImm)]; ok {
		// 				instrStr += fmt.Sprintf(" ; %s", name)
		// 			} else if cstr, err := m.GetCString(adrImm); err == nil {
		// 				if utils.IsASCII(cstr) {
		// 					if len(cstr) > 200 {
		// 						instrStr += fmt.Sprintf(" ; %#v...", cstr[:200])
		// 					} else if len(cstr) > 1 {
		// 						instrStr += fmt.Sprintf(" ; %#v", cstr)
		// 					}
		// 				}
		// 			}
		// 		}

		// 		if (prevInstr != nil && prevInstr.Operation == disassemble.ARM64_ADRP) && (instruction.Operation == disassemble.ARM64_ADD || instruction.Operation == disassemble.ARM64_LDR) {
		// 			adrpRegister := prevInstr.Operands[0].Registers[0]
		// 			adrpImm := prevInstr.Operands[1].Immediate
		// 			if instruction.Operation == disassemble.ARM64_LDR && adrpRegister == instruction.Operands[1].Registers[0] {
		// 				adrpImm += instruction.Operands[1].Immediate
		// 			} else if instruction.Operation == disassemble.ARM64_ADD && adrpRegister == instruction.Operands[1].Registers[0] {
		// 				adrpImm += instruction.Operands[2].Immediate
		// 			}
		// 			if name, ok := f.AddressToSymbol[uint64(adrpImm)]; ok {
		// 				instrStr += fmt.Sprintf(" ; %s", name)
		// 			} else if cstr, err := m.GetCString(adrpImm); err == nil {
		// 				if utils.IsASCII(cstr) {
		// 					if len(cstr) > 200 {
		// 						instrStr += fmt.Sprintf(" ; %#v...", cstr[:200])
		// 					} else if len(cstr) > 1 {
		// 						instrStr += fmt.Sprintf(" ; %#v", cstr)
		// 					}
		// 				}
		// 			}
		// 		}
		// 	}

		// 	if isMiddle && startVMAddr == symAddr {
		// 		fmt.Printf("👉%08x:  %s\t%s\n", uint64(startAddr), disassemble.GetOpCodeByteString(instrValue), instrStr)
		// 	} else {
		// 		fmt.Printf("%#08x:  %s\t%s\n", uint64(startAddr), disassemble.GetOpCodeByteString(instrValue), instrStr)
		// 	}

		// 	prevInstr = instruction
		// 	startAddr += uint64(binary.Size(uint32(0)))
		// }

		return nil
	},
}
