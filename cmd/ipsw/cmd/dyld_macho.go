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
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/apex/log"
	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	dyldCmd.AddCommand(dyldMachoCmd)

	dyldMachoCmd.Flags().BoolP("all", "a", false, "Parse ALL dylibs")
	dyldMachoCmd.Flags().BoolP("loads", "l", false, "Print the load commands")
	dyldMachoCmd.Flags().BoolP("objc", "o", false, "Print ObjC info")
	dyldMachoCmd.Flags().BoolP("objc-refs", "r", false, "Print ObjC references")
	dyldMachoCmd.Flags().BoolP("symbols", "n", false, "Print symbols")
	dyldMachoCmd.Flags().BoolP("starts", "f", false, "Print function starts")
	dyldMachoCmd.Flags().BoolP("strings", "s", false, "Print cstrings")
	// dyldMachoCmd.Flags().BoolP("stubs", "b", false, "Print stubs")

	dyldMachoCmd.Flags().BoolP("extract", "x", false, "🚧 Extract the dylib")
	// dyldMachoCmd.Flags().StringP("out", "", "", "🚧 Directory to extract the dylib")

	dyldMachoCmd.MarkZshCompPositionalArgumentFile(1)
}

// dyldMachoCmd represents the macho command
var dyldMachoCmd = &cobra.Command{
	Use:   "macho <dyld_shared_cache> <dylib>",
	Short: "Parse a dylib file",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		showLoadCommands, _ := cmd.Flags().GetBool("loads")
		showObjC, _ := cmd.Flags().GetBool("objc")
		showObjcRefs, _ := cmd.Flags().GetBool("objc-refs")
		dumpSymbols, _ := cmd.Flags().GetBool("symbols")
		showFuncStarts, _ := cmd.Flags().GetBool("starts")
		dumpStrings, _ := cmd.Flags().GetBool("strings")
		// dumpStubs, _ := cmd.Flags().GetBool("stubs")
		dumpALL, _ := cmd.Flags().GetBool("all")
		extractDylib, _ := cmd.Flags().GetBool("extract")

		onlyFuncStarts := !showLoadCommands && !showObjC && showFuncStarts

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

		if len(args) > 1 || dumpALL {

			var images []*dyld.CacheImage

			if dumpALL {
				images = f.Images
			} else {
				if img := f.Image(args[1]); img != nil {
					images = append(images, img)
				} else {
					log.Errorf("dylib %s not found in %s", args[1], dscPath)
					return nil
				}
			}

			for _, i := range images {

				if dumpALL {
					fmt.Printf("IMAGE: %s\n\n", i.Name)
				}

				m, err := i.GetMacho()
				if err != nil {
					log.Warnf("failed to parse full MachO for %s: %v", i.Name, err)
					m, err = i.GetPartialMacho()
					if err != nil {
						return err
					}
				}

				if extractDylib {
					var dcf *fixupchains.DyldChainedFixups
					if m.HasFixups() {
						dcf, err = m.DyldChainedFixups()
						if err != nil {
							return fmt.Errorf("failed to parse fixups from in memory MachO: %v", err)
						}
					}
					err = m.Export(filepath.Join(filepath.Dir(dscPath), filepath.Base(i.Name)), dcf, m.GetBaseAddress())
					if err != nil {
						return fmt.Errorf("failed to export entry MachO %s; %v", i.Name, err)
					}
					log.Infof("Created %s", filepath.Join(filepath.Dir(dscPath), filepath.Base(i.Name)))
					return nil
				}

				if showLoadCommands || !showObjC && !dumpSymbols && !dumpStrings && !showFuncStarts {
					fmt.Println(m.FileTOC.String())
				}

				if showObjC {
					fmt.Println("Objective-C")
					fmt.Println("===========")
					if m.HasObjC() {
						if info, err := m.GetObjCImageInfo(); err == nil {
							// fmt.Println(m.GetObjCInfo())
							fmt.Println(info.Flags)
						}

						if protos, err := m.GetObjCProtocols(); err == nil {
							for _, proto := range protos {
								if Verbose {
									fmt.Println(proto.Verbose())
								} else {
									fmt.Println(proto.String())
								}
							}
						}
						if classes, err := m.GetObjCClasses(); err == nil {
							for _, class := range classes {
								if Verbose {
									fmt.Println(class.Verbose())
								} else {
									fmt.Println(class.String())
								}
							}
						} else {
							log.Error(err.Error())
						}
						if nlclasses, err := m.GetObjCPlusLoadClasses(); err == nil {
							for _, class := range nlclasses {
								if Verbose {
									fmt.Println(class.Verbose())
								} else {
									fmt.Println(class.String())
								}
							}
						}
						if cats, err := m.GetObjCCategories(); err == nil {
							for _, cat := range cats {
								if Verbose {
									fmt.Println(cat.Verbose())
								} else {
									fmt.Println(cat.String())
								}
							}
						}
						if showObjcRefs {
							if protRefs, err := m.GetObjCProtoReferences(); err == nil {
								fmt.Printf("\n@protocol refs\n")
								for off, prot := range protRefs {
									fmt.Printf("0x%011x => 0x%011x: %s\n", off, prot.Ptr, prot.Name)
								}
							}
							if clsRefs, err := m.GetObjCClassReferences(); err == nil {
								fmt.Printf("\n@class refs\n")
								for off, cls := range clsRefs {
									fmt.Printf("0x%011x => 0x%011x: %s\n", off, cls.ClassPtr, cls.Name)
									// if Verbose {
									// 	fmt.Println(cls.Verbose())
									// } else {
									// 	fmt.Println(cls.String())
									// }
								}
							}
							if supRefs, err := m.GetObjCSuperReferences(); err == nil {
								fmt.Printf("\n@super refs\n")
								for off, sup := range supRefs {
									fmt.Printf("0x%011x => 0x%011x: %s\n", off, sup.ClassPtr, sup.Name)
								}
							}
							if selRefs, err := m.GetObjCSelectorReferences(); err == nil {
								fmt.Printf("\n@selectors refs\n")
								for off, sel := range selRefs {
									fmt.Printf("0x%011x => 0x%011x: %s\n", off, sel.VMAddr, sel.Name)
								}
							}
							if methods, err := m.GetObjCMethodNames(); err == nil {
								fmt.Printf("\n@methods\n")
								for method, vmaddr := range methods {
									fmt.Printf("0x%011x: %s\n", vmaddr, method)
								}
							}
						}

					} else {
						fmt.Println("  - no objc")
					}
					fmt.Println()
				}

				if showFuncStarts {
					if !onlyFuncStarts {
						fmt.Println("FUNCTION STARTS")
						fmt.Println("===============")
					}
					if m.FunctionStarts() != nil {
						for _, fn := range m.GetFunctions() {
							if Verbose {
								fmt.Printf("%#016x-%#016x\n", fn.StartAddr, fn.EndAddr)
							} else {
								fmt.Printf("0x%016X\n", fn.StartAddr)
							}
						}
					}
				}

				if dumpSymbols {
					w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.Debug)
					if m.Symtab != nil {
						fmt.Println("SYMBOLS")
						fmt.Println("=======")
						var sec string
						for _, sym := range m.Symtab.Syms {
							if sym.Sect > 0 && int(sym.Sect) <= len(m.Sections) {
								sec = fmt.Sprintf("%s.%s", m.Sections[sym.Sect-1].Seg, m.Sections[sym.Sect-1].Name)
							}
							fmt.Fprintf(w, "%#016x:  <%s> \t %s\n", sym.Value, sym.Type.String(sec), sym.Name)
							// fmt.Printf("0x%016X <%s> %s\n", sym.Value, sym.Type.String(sec), sym.Name)
						}
						w.Flush()
					}
					// Dedup these symbols (has repeats but also additional symbols??)
					if m.DyldExportsTrie() != nil && m.DyldExportsTrie().Size > 0 {
						fmt.Printf("\nDyldExport SYMBOLS\n")
						fmt.Println("------------------")
						exports, err := m.DyldExports()
						if err != nil {
							return err
						}
						for _, export := range exports {
							if export.Flags.ReExport() {
								export.FoundInDylib = m.ImportedLibraries()[export.Other-1]
								if rexpSym, err := f.FindExportedSymbolInImage(export.FoundInDylib, export.ReExport); err == nil {
									export.Address = rexpSym.Address
								}
							}
							fmt.Println(export)
						}
					}
					if cfstrs, err := m.GetCFStrings(); err == nil {
						fmt.Printf("\nCFStrings\n")
						fmt.Println("---------")
						for _, cfstr := range cfstrs {
							fmt.Printf("%#016x:  %#v\n", cfstr.Address, cfstr.Name)
						}
					}
				}

				if dumpStrings {
					fmt.Printf("\nCStrings\n")
					fmt.Println("--------")
					for _, sec := range m.Sections {

						if sec.Flags.IsCstringLiterals() || strings.Contains(sec.Name, "cstring") {
							dat, err := sec.Data()
							if err != nil {
								return fmt.Errorf("failed to read cstrings in %s.%s: %v", sec.Seg, sec.Name, err)
							}

							csr := bytes.NewBuffer(dat)

							for {
								pos := sec.Addr + uint64(csr.Cap()-csr.Len())

								s, err := csr.ReadString('\x00')

								if err == io.EOF {
									break
								}

								if err != nil {
									return fmt.Errorf("failed to read string: %v", err)
								}

								if len(s) > 0 {
									fmt.Printf("%#x: %#v\n", pos, strings.Trim(s, "\x00"))
								}
							}
						}
					}
				}

				// if dumpStubs {
				// 	if err := f.AnalyzeImage(i); err != nil {
				// 		return err
				// 	}
				// 	for stubAddr, addr := range i.Analysis.SymbolStubs {
				// 		if symName, ok := f.AddressToSymbol[addr]; ok {
				// 			fmt.Printf("%#x: %s\n", stubAddr, symName)
				// 			// return nil
				// 		}
				// 	}
				// }
			}
		} else {
			log.Error("you must supply a dylib MachO to parse")
		}

		return nil
	},
}
