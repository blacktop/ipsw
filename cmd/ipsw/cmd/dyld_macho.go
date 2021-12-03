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
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/vbauerster/mpb/v7"
	"github.com/vbauerster/mpb/v7/decor"
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
	dyldMachoCmd.Flags().BoolP("stubs", "b", false, "Print stubs")

	dyldMachoCmd.Flags().BoolP("extract", "x", false, "🚧 Extract the dylib")
	dyldMachoCmd.Flags().String("output", "", "Directory to extract the dylib(s)")
	dyldMachoCmd.Flags().Bool("force", false, "Overwrite existing extracted dylib(s)")

	dyldMachoCmd.MarkZshCompPositionalArgumentFile(1)
}

func rebaseMachO(dsc *dyld.File, machoPath string) error {
	f, err := os.OpenFile(machoPath, os.O_RDWR, 0755)
	if err != nil {
		return fmt.Errorf("failed to open exported MachO %s: %v", machoPath, err)
	}
	defer f.Close()

	mm, err := macho.NewFile(f)
	if err != nil {
		return err
	}

	for _, seg := range mm.Segments() {
		uuid, mapping, err := dsc.GetMappingForVMAddress(seg.Addr)
		if err != nil {
			return err
		}

		if mapping.SlideInfoOffset == 0 {
			continue
		}

		startAddr := seg.Addr - mapping.Address
		endAddr := ((seg.Addr + seg.Memsz) - mapping.Address) + uint64(dsc.SlideInfo.GetPageSize())

		start := startAddr / uint64(dsc.SlideInfo.GetPageSize())
		end := endAddr / uint64(dsc.SlideInfo.GetPageSize())

		rebases, err := dsc.GetRebaseInfoForPages(uuid, mapping, start, end)
		if err != nil {
			return err
		}

		for _, rebase := range rebases {
			off, err := mm.GetOffset(rebase.CacheVMAddress)
			if err != nil {
				continue
			}
			if _, err := f.Seek(int64(off), io.SeekStart); err != nil {
				return fmt.Errorf("failed to seek in exported file to offset %#x from the start: %v", off, err)
			}
			if err := binary.Write(f, dsc.ByteOrder, rebase.Target); err != nil {
				return fmt.Errorf("failed to write rebase address %#x: %v", rebase.Target, err)
			}
		}
	}

	return nil
}

// dyldMachoCmd represents the macho command
var dyldMachoCmd = &cobra.Command{
	Use:   "macho <dyld_shared_cache> <dylib>",
	Short: "Parse a dylib file",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		var bar *mpb.Bar

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		showLoadCommands, _ := cmd.Flags().GetBool("loads")
		showObjC, _ := cmd.Flags().GetBool("objc")
		showObjcRefs, _ := cmd.Flags().GetBool("objc-refs")
		dumpSymbols, _ := cmd.Flags().GetBool("symbols")
		showFuncStarts, _ := cmd.Flags().GetBool("starts")
		dumpStrings, _ := cmd.Flags().GetBool("strings")
		dumpStubs, _ := cmd.Flags().GetBool("stubs")
		dumpALL, _ := cmd.Flags().GetBool("all")
		extractDylib, _ := cmd.Flags().GetBool("extract")
		extractPath, _ := cmd.Flags().GetString("output")
		forceExtract, _ := cmd.Flags().GetBool("force")

		onlyFuncStarts := !showLoadCommands && !showObjC && !dumpStubs && showFuncStarts
		onlyStubs := !showLoadCommands && !showObjC && !showFuncStarts && dumpStubs

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
				// initialize progress bar
				p := mpb.New(mpb.WithWidth(80))
				// adding a single bar, which will inherit container's width
				bar = p.Add(int64(len(images)),
					// progress bar filler with customized style
					mpb.NewBarFiller(mpb.BarStyle().Lbound("[").Filler("=").Tip(">").Padding("-").Rbound("|")),
					mpb.PrependDecorators(
						decor.Name("     ", decor.WC{W: len("     ") + 1, C: decor.DidentRight}),
						// replace ETA decorator with "done" message, OnComplete event
						decor.OnComplete(
							decor.AverageETA(decor.ET_STYLE_GO, decor.WC{W: 4}), "✅ ",
						),
					),
					mpb.AppendDecorators(
						decor.Percentage(),
						// decor.OnComplete(decor.EwmaETA(decor.ET_STYLE_GO, float64(len(images))/2048), "✅ "),
						decor.Name(" ] "),
					),
				)
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
					log.WithField("name", i.Name).Debug("Image")
				}

				m, err := i.GetMacho()
				if err != nil {
					log.Warnf("failed to parse full MachO for %s: %v", i.Name, err)
					if extractDylib {
						continue
					}
					m, err = i.GetPartialMacho()
					if err != nil {
						return err
					}
				}
				defer m.Close()

				if extractDylib {

					folder := filepath.Dir(dscPath) // default to folder of shared cache
					if len(extractPath) > 0 {
						folder = extractPath
					}
					fname := filepath.Join(folder, filepath.Base(i.Name)) // default to NOT full dylib path
					if dumpALL {
						fname = filepath.Join(folder, i.Name)
					}

					if _, err := os.Stat(fname); os.IsNotExist(err) || forceExtract {
						var dcf *fixupchains.DyldChainedFixups
						if m.HasFixups() {
							dcf, err = m.DyldChainedFixups()
							if err != nil {
								return fmt.Errorf("failed to parse fixups from in memory MachO: %v", err)
							}
						}

						f.GetLocalSymbolsForImage(i)

						// cc, err := m.GetObjCClasses()
						// if err != nil {
						// 	return err
						// }
						// for _, c := range cc {
						// 	fmt.Println(c)
						// }

						err = m.Export(fname, dcf, m.GetBaseAddress(), i.GetLocalSymbols())
						if err != nil {
							return fmt.Errorf("failed to export entry MachO %s; %v", i.Name, err)
						}

						if err := rebaseMachO(f, fname); err != nil {
							return fmt.Errorf("failed to rebase macho via cache slide info: %v", err)
						}
						if !dumpALL {
							log.Infof("Created %s", fname)
						} else {
							bar.Increment()
						}
					} else {
						if !dumpALL {
							log.Warnf("dylib already exists: %s", fname)
						} else {
							bar.Increment()
						}
					}
					continue
				}

				if showLoadCommands || !showObjC && !dumpSymbols && !dumpStrings && !showFuncStarts && !dumpStubs {
					fmt.Println(m.FileTOC.String())
				}

				if showObjC {
					fmt.Println("Objective-C")
					fmt.Println("===========")
					if m.HasObjC() {
						if info, err := m.GetObjCImageInfo(); err == nil {
							fmt.Println(info.Flags)
						} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
							log.Error(err.Error())
						}
						if Verbose {
							fmt.Println(m.GetObjCToc())
						}
						if protos, err := m.GetObjCProtocols(); err == nil {
							for _, proto := range protos {
								if Verbose {
									fmt.Println(proto.Verbose())
								} else {
									fmt.Println(proto.String())
								}
							}
						} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
							log.Error(err.Error())
						}
						if classes, err := m.GetObjCClasses(); err == nil {
							for _, class := range classes {
								if Verbose {
									fmt.Println(class.Verbose())
								} else {
									fmt.Println(class.String())
								}
							}
						} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
							log.Error(err.Error())
						}
						if cats, err := m.GetObjCCategories(); err == nil {
							for _, cat := range cats {
								if Verbose {
									fmt.Println(cat.Verbose())
								} else {
									fmt.Println(cat.String())
								}
							}
						} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
							log.Error(err.Error())
						}
						if showObjcRefs {
							if protRefs, err := m.GetObjCProtoReferences(); err == nil {
								fmt.Printf("\n@protocol refs\n")
								for off, prot := range protRefs {
									fmt.Printf("0x%011x => 0x%011x: %s\n", off, prot.Ptr, prot.Name)
								}
							} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
								log.Error(err.Error())
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
							} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
								log.Error(err.Error())
							}
							if supRefs, err := m.GetObjCSuperReferences(); err == nil {
								fmt.Printf("\n@super refs\n")
								for off, sup := range supRefs {
									fmt.Printf("0x%011x => 0x%011x: %s\n", off, sup.ClassPtr, sup.Name)
								}
							} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
								log.Error(err.Error())
							}
							if selRefs, err := m.GetObjCSelectorReferences(); err == nil {
								fmt.Printf("\n@selectors refs\n")
								for off, sel := range selRefs {
									fmt.Printf("0x%011x => 0x%011x: %s\n", off, sel.VMAddr, sel.Name)
								}
							} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
								log.Error(err.Error())
							}
							if methods, err := m.GetObjCMethodNames(); err == nil {
								fmt.Printf("\n@methods\n")
								for method, vmaddr := range methods {
									fmt.Printf("0x%011x: %s\n", vmaddr, method)
								}
							} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
								log.Error(err.Error())
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
					w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
					if m.Symtab != nil {
						fmt.Println("SYMBOLS")
						fmt.Println("=======")
						var sec string
						for _, sym := range m.Symtab.Syms {
							if sym.Sect > 0 && int(sym.Sect) <= len(m.Sections) {
								sec = fmt.Sprintf("%s.%s", m.Sections[sym.Sect-1].Seg, m.Sections[sym.Sect-1].Name)
							}
							fmt.Fprintf(w, "%#09x:  <%s> \t %s\n", sym.Value, sym.Type.String(sec), sym.Name)
							// fmt.Printf("0x%016X <%s> %s\n", sym.Value, sym.Type.String(sec), sym.Name)
						}
						w.Flush()
					}
					if binds, err := m.GetBindInfo(); err == nil {
						fmt.Printf("\nDyld Binds\n")
						fmt.Println("----------")
						for _, bind := range binds {
							fmt.Fprintf(w, "%#09x:\t(%s.%s|from %s)\t%s\n", bind.Start+bind.Offset, bind.Segment, bind.Section, bind.Dylib, bind.Name)
						}
						w.Flush()
					}
					// Dedup these symbols (has repeats but also additional symbols??)
					if m.DyldExportsTrie() != nil && m.DyldExportsTrie().Size > 0 && Verbose {
						fmt.Printf("\nDyld Exports\n")
						fmt.Println("------------")
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

					if cfstrs, err := m.GetCFStrings(); err == nil {
						fmt.Printf("\nCFStrings\n")
						fmt.Println("---------")
						for _, cfstr := range cfstrs {
							fmt.Printf("%#09x:  %#v\n", cfstr.Address, cfstr.Name)
						}
					}
				}

				if dumpStubs {
					if !onlyStubs {
						fmt.Printf("\nStubs\n")
						fmt.Println("=====")
					}
					if err := f.AnalyzeImage(i); err != nil {
						return err
					}
					for stubAddr, addr := range i.Analysis.SymbolStubs {
						if symName, ok := f.AddressToSymbol[addr]; ok {
							fmt.Printf("%#x => %#x: %s\n", stubAddr, addr, symName)
						}
					}
				}
			}
		} else {
			log.Error("you must supply a dylib MachO to parse")
		}

		return nil
	},
}
