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
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	dyldCmd.AddCommand(dyldMachoCmd)

	dyldMachoCmd.Flags().BoolP("loads", "l", false, "Print the load commands")
	dyldMachoCmd.Flags().BoolP("objc", "o", false, "Print ObjC info")
	dyldMachoCmd.Flags().BoolP("symbols", "n", false, "Print symbols")
	dyldMachoCmd.Flags().BoolP("starts", "f", false, "Print function starts")
	dyldMachoCmd.Flags().BoolP("strings", "s", false, "Print cstrings")

	dyldMachoCmd.MarkZshCompPositionalArgumentFile(1)
}

// dyldMachoCmd represents the macho command
var dyldMachoCmd = &cobra.Command{
	Use:   "macho [options] <dyld_shared_cache> <dylib>",
	Short: "Parse a dylib file",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		showLoadCommands, _ := cmd.Flags().GetBool("loads")
		showObjC, _ := cmd.Flags().GetBool("objc")
		dumpSymbols, _ := cmd.Flags().GetBool("symbols")
		showFuncStarts, _ := cmd.Flags().GetBool("starts")
		dumpStrings, _ := cmd.Flags().GetBool("strings")

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

		if len(args) > 1 {
			if i := f.Image(args[1]); i != nil {
				m, err := i.GetMacho()
				if err != nil {
					return err
				}

				if showLoadCommands || !showObjC && !dumpSymbols && !dumpStrings {
					fmt.Println(m.FileTOC.String())
				}

				if showObjC {
					fmt.Println("Objective-C")
					fmt.Println("===========")
					if m.HasObjC() {
						if info, err := m.GetObjCImageInfo(); err == nil {
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
						if selRefs, err := m.GetObjCSelectorReferences(); err == nil {
							fmt.Println("@selectors refs")
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
					fmt.Println("SYMBOLS")
					fmt.Println("=======")
					var sec string
					w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.Debug)
					for _, sym := range m.Symtab.Syms {
						if sym.Sect > 0 && int(sym.Sect) <= len(m.Sections) {
							sec = fmt.Sprintf("%s.%s", m.Sections[sym.Sect-1].Seg, m.Sections[sym.Sect-1].Name)
						}
						fmt.Fprintf(w, "%#016x:  <%s> \t %s\n", sym.Value, sym.Type.String(sec), sym.Name)
						// fmt.Printf("0x%016X <%s> %s\n", sym.Value, sym.Type.String(sec), sym.Name)
					}
					w.Flush()
					// Dedup these symbols (has repeats but also additional symbols??)
					if m.DyldExportsTrie() != nil && m.DyldExportsTrie().Size > 0 {
						fmt.Printf("\nDyldExport SYMBOLS\n")
						fmt.Println("------------------")
						exports, err := m.DyldExports()
						if err != nil {
							return err
						}
						for _, export := range exports {
							fmt.Fprintf(w, "%#016x:  <%s> \t %s\n", export.Address, export.Flags, export.Name)
						}
						w.Flush()
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
					for _, sec := range m.Sections {

						if sec.Flags.IsCstringLiterals() {
							dat, err := sec.Data()
							if err != nil {
								return fmt.Errorf("failed to read cstrings in %s.%s: %v", sec.Seg, sec.Name, err)
							}

							csr := bytes.NewBuffer(dat[:])

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

			} else {
				log.Errorf("dylib %s not found in %s", args[1], dscPath)
			}
		} else {
			log.Error("you must supply a dylib MachO to parse")
		}

		return nil
	},
}
