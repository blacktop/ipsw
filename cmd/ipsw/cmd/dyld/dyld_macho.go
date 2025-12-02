/*
Copyright © 2018-2025 blacktop

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
package dyld

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-macho/pkg/swift"
	"github.com/blacktop/ipsw/internal/colors"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/demangle"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	onlyLoadCommands = 1 << 0
	onlyObjC         = 1 << 1
	onlySwift        = 1 << 2
	onlySymbols      = 1 << 3
	onlyFuncStarts   = 1 << 4
	onlyStrings      = 1 << 5
	onlyStubs        = 1 << 6
	onlySearch       = 1 << 7
)

func init() {
	DyldCmd.AddCommand(MachoCmd)
	MachoCmd.Flags().BoolP("all", "a", false, "Parse ALL dylibs")
	MachoCmd.Flags().BoolP("loads", "l", false, "Print the load commands")
	MachoCmd.Flags().BoolP("json", "j", false, "Print the TOC as JSON")
	MachoCmd.Flags().BoolP("objc", "o", false, "Print ObjC info")
	MachoCmd.Flags().BoolP("objc-refs", "r", false, "Print ObjC references")
	MachoCmd.Flags().BoolP("swift", "w", false, "Print Swift info")
	MachoCmd.Flags().Bool("swift-all", false, "Print all other Swift sections info")
	MachoCmd.Flags().BoolP("symbols", "n", false, "Print symbols")
	MachoCmd.Flags().Bool("demangle", false, "Demangle symbol names")
	MachoCmd.Flags().BoolP("starts", "f", false, "Print function starts")
	MachoCmd.Flags().BoolP("strings", "s", false, "Print cstrings")
	MachoCmd.Flags().BoolP("stubs", "b", false, "Print stubs")
	MachoCmd.Flags().String("search", "", "Search for byte pattern")
	MachoCmd.Flags().BoolP("extract", "x", false, "🚧 Extract the dylib")
	MachoCmd.Flags().String("output", "", "Directory to extract the dylib(s)")
	MachoCmd.Flags().Bool("force", false, "Overwrite existing extracted dylib(s)")

	viper.BindPFlag("dyld.macho.all", MachoCmd.Flags().Lookup("all"))
	viper.BindPFlag("dyld.macho.loads", MachoCmd.Flags().Lookup("loads"))
	viper.BindPFlag("dyld.macho.json", MachoCmd.Flags().Lookup("json"))
	viper.BindPFlag("dyld.macho.objc", MachoCmd.Flags().Lookup("objc"))
	viper.BindPFlag("dyld.macho.objc-refs", MachoCmd.Flags().Lookup("objc-refs"))
	viper.BindPFlag("dyld.macho.swift", MachoCmd.Flags().Lookup("swift"))
	viper.BindPFlag("dyld.macho.swift-all", MachoCmd.Flags().Lookup("swift-all"))
	viper.BindPFlag("dyld.macho.symbols", MachoCmd.Flags().Lookup("symbols"))
	viper.BindPFlag("dyld.macho.demangle", MachoCmd.Flags().Lookup("demangle"))
	viper.BindPFlag("dyld.macho.starts", MachoCmd.Flags().Lookup("starts"))
	viper.BindPFlag("dyld.macho.strings", MachoCmd.Flags().Lookup("strings"))
	viper.BindPFlag("dyld.macho.stubs", MachoCmd.Flags().Lookup("stubs"))
	viper.BindPFlag("dyld.macho.search", MachoCmd.Flags().Lookup("search"))
	viper.BindPFlag("dyld.macho.extract", MachoCmd.Flags().Lookup("extract"))
	viper.BindPFlag("dyld.macho.output", MachoCmd.Flags().Lookup("output"))
	viper.BindPFlag("dyld.macho.force", MachoCmd.Flags().Lookup("force"))
}

// MachoCmd represents the macho command
var MachoCmd = &cobra.Command{
	Use:     "macho <DSC> <DYLIB>",
	Aliases: []string{"m"},
	Short:   "Parse an incache dylib file",
	Args:    cobra.MinimumNArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) == 1 {
			return getImages(args[0]), cobra.ShellCompDirectiveDefault
		}
		return getDSCs(toComplete), cobra.ShellCompDirectiveDefault
	},
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		// flags
		verbose := viper.GetBool("verbose")
		showLoadCommands := viper.GetBool("dyld.macho.loads")
		showLoadCommandsAsJSON := viper.GetBool("dyld.macho.json")
		showObjC := viper.GetBool("dyld.macho.objc")
		showObjcRefs := viper.GetBool("dyld.macho.objc-refs")
		showSwift := viper.GetBool("dyld.macho.swift")
		showSwiftAll := viper.GetBool("dyld.macho.swift-all")
		showSymbols := viper.GetBool("dyld.macho.symbols")
		doDemangle := viper.GetBool("dyld.macho.demangle")
		showFuncStarts := viper.GetBool("dyld.macho.starts")
		showStrings := viper.GetBool("dyld.macho.strings")
		showStubs := viper.GetBool("dyld.macho.stubs")
		searchPattern := viper.GetString("dyld.macho.search")
		dumpALL := viper.GetBool("dyld.macho.all")
		extractDylib := viper.GetBool("dyld.macho.extract")
		extractPath := viper.GetString("dyld.macho.output")
		forceExtract := viper.GetBool("dyld.macho.force")
		// validate flags
		if doDemangle && (!showSymbols && !showSwift) {
			return fmt.Errorf("you must also supply --symbols OR --swift flag to demangle")
		} else if showSwiftAll && !showSwift {
			return fmt.Errorf("you must use --swift flag to use --swift-all")
		} else if showObjcRefs && !showObjC {
			return fmt.Errorf("you must use --objc flag to use --objc-refs")
		}

		var options uint32
		for i, opt := range []bool{
			showLoadCommands, showObjC, showSwift, showSymbols,
			showFuncStarts, showStrings, showStubs, len(searchPattern) > 0,
		} {
			if opt {
				options |= 1 << i
			}
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

		if len(args) > 1 || dumpALL {

			var images []*dyld.CacheImage

			foundPattern := false

			if dumpALL {
				images = f.Images
			} else {
				image, err := f.Image(args[1])
				if err != nil {
					return fmt.Errorf("image not in %s: %v", dscPath, err)
				}
				images = append(images, image)
			}

			for _, image := range images {
				if dumpALL {
					log.WithField("name", image.Name).Debug("Image")
				}

				m, err := image.GetMacho()
				if err != nil {
					log.Warnf("failed to parse full MachO for %s: %v", image.Name, err)
					if extractDylib {
						continue
					}
					m, err = image.GetPartialMacho()
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
					fname := filepath.Join(folder, filepath.Base(image.Name)) // default to NOT full dylib path
					if dumpALL {
						fname = filepath.Join(folder, image.Name)
					}

					if _, err := os.Stat(fname); os.IsNotExist(err) || forceExtract {
						var dcf *fixupchains.DyldChainedFixups
						if m.HasFixups() {
							dcf, err = m.DyldChainedFixups()
							if err != nil {
								return fmt.Errorf("failed to parse fixups from in memory MachO: %v", err)
							}
						}

						image.ParseLocalSymbols(false)

						// cc, err := m.GetObjCClasses()
						// if err != nil {
						// 	return err
						// }
						// for _, c := range cc {
						// 	fmt.Println(c)
						// }

						err = m.Export(fname, dcf, m.GetBaseAddress(), image.GetLocalSymbolsAsMachoSymbols())
						if err != nil {
							return fmt.Errorf("failed to export entry MachO %s; %v", image.Name, err)
						}

						if err := rebaseMachO(f, fname); err != nil {
							return fmt.Errorf("failed to rebase macho via cache slide info: %v", err)
						}
						if !dumpALL {
							log.Infof("Created %s", fname)
						}
					} else {
						if !dumpALL {
							log.Warnf("dylib already exists: %s", fname)
						}
					}
					continue
				}

				if showLoadCommands || options == 0 {
					if showLoadCommandsAsJSON {
						dat, err := m.FileTOC.MarshalJSON()
						if err != nil {
							return fmt.Errorf("failed to marshal MachO table of contents as JSON: %v", err)
						}
						fmt.Println(string(dat))
					} else {
						fmt.Println(m.FileTOC.String())
					}
				}

				if showObjC {
					if options != onlyObjC {
						fmt.Println("Objective-C")
						fmt.Println("===========")
					}
					if m.HasObjC() {
						o, err := mcmd.NewObjC(m, f, &mcmd.ObjcConfig{
							Verbose:  verbose,
							Addrs:    true,
							ObjcRefs: showObjcRefs,
							Demangle: doDemangle,
							Color:    colors.Active(),
							Theme:    "nord",
						})
						if err != nil {
							return fmt.Errorf("failed to create ObjC object: %v", err)
						}
						if err := o.Dump(); err != nil {
							return fmt.Errorf("failed to dump objc data: %v", err)
						}
					} else {
						fmt.Println("  - no objc")
					}
					println()
				}

				fixedLocals := false

				if showSwift {
					if options != onlySwift {
						fmt.Println("Swift")
						fmt.Println("=====")
					}
					if m.HasSwift() {
						image.ParseLocalSymbols(false) // parse local symbols for swift demangling
						if m.Symtab != nil {
							for idx, sym := range m.Symtab.Syms {
								if sym.Value != 0 {
									if sym.Name == "<redacted>" {
										if name, ok := f.AddressToSymbol[sym.Value]; ok {
											m.Symtab.Syms[idx].Name = name
										}
									}
								}
								if doDemangle {
									if strings.HasPrefix(sym.Name, "_$s") || strings.HasPrefix(sym.Name, "$s") {
										m.Symtab.Syms[idx].Name, _ = swift.Demangle(sym.Name)
									} else if strings.HasPrefix(sym.Name, "__Z") || strings.HasPrefix(sym.Name, "_Z") {
										m.Symtab.Syms[idx].Name = demangle.Do(sym.Name, false, false)
									}
								}
							}
						}
						fixedLocals = true
						s, err := mcmd.NewSwift(m, f, &mcmd.SwiftConfig{
							Verbose:  verbose,
							Addrs:    true,
							All:      showSwiftAll,
							Demangle: doDemangle,
							Color:    colors.Active(),
							Theme:    "nord",
						})
						if err != nil {
							return fmt.Errorf("failed to create Swift object: %v", err)
						}
						if err := s.Dump(); err != nil {
							return fmt.Errorf("failed to dump swift data: %v", err)
						}
					} else {
						fmt.Print("  - no swift")
					}
					println()
				}

				if showFuncStarts {
					if options != onlyFuncStarts {
						fmt.Println("FUNCTION STARTS")
						fmt.Println("===============")
					}
					if m.FunctionStarts() != nil {
						for _, fn := range m.GetFunctions() {
							if verbose {
								fmt.Printf("%#016x-%#016x\n", fn.StartAddr, fn.EndAddr)
							} else {
								fmt.Printf("0x%016X\n", fn.StartAddr)
							}
						}
					}
					println()
				}

				if showSymbols {
					image.ParseLocalSymbols(false)
					if options != onlySymbols {
						fmt.Println("SYMBOLS")
						fmt.Println("=======")
					}
					if m.Symtab != nil {
						fmt.Println("Symtab")
						fmt.Println("------")
						undeflush := false
						for _, sym := range m.Symtab.Syms {
							if sym.Type.IsUndefinedSym() && !undeflush {
								undeflush = true
							}
							if !fixedLocals && sym.Name == "<redacted>" {
								if name, ok := f.AddressToSymbol[sym.Value]; ok {
									sym.Name = name
								}
							}
							if doDemangle {
								if strings.HasPrefix(sym.Name, "_associated conformance ") {
									if _, rest, ok := strings.Cut(sym.Name, "_associated conformance "); ok {
										sym.Name, _ = swift.Demangle("_$s" + rest)
										sym.Name = "_associated conformance " + sym.Name
									}
								} else if strings.HasPrefix(sym.Name, "_symbolic ") {
									if _, rest, ok := strings.Cut(sym.Name, "_symbolic "); ok {
										rest = strings.TrimPrefix(rest, "_____ ")
										if !strings.HasPrefix(rest, "$s") && !strings.HasPrefix(rest, "_$s") {
											rest = "_$s" + rest
										}
										sym.Name, _ = swift.Demangle(rest)
										sym.Name = "_symbolic " + sym.Name
									}
								} else if strings.HasPrefix(sym.Name, "_$s") || strings.HasPrefix(sym.Name, "$s") { // TODO: better detect swift symbols
									sym.Name, _ = swift.Demangle(sym.Name)
								} else {
									sym.Name = demangle.Do(sym.Name, false, false)
								}
							}
							if sym.Value == 0 {
								fmt.Printf("              %s\n", strings.Join([]string{symTypeColor(sym.GetType(m)), symNameColor(sym.Name), symLibColor(sym.GetLib(m))}, "\t"))
							} else {
								fmt.Printf("%s:  %s\n", symAddrColor("%#09x", sym.Value), strings.Join([]string{symTypeColor(sym.GetType(m)), symNameColor(sym.Name), symLibColor(sym.GetLib(m))}, "\t"))
							}
						}
					} else {
						fmt.Println("  - no symbol table")
					}
					if binds, err := m.GetBindInfo(); err == nil {
						fmt.Printf("\nDyld Binds\n")
						fmt.Println("----------")
						for _, bind := range binds {
							if doDemangle {
								bind.Name, _ = swift.Demangle(bind.Name)
							}
							fmt.Printf("%#09x:\t(%s.%s|from %s)\t%s\n", bind.Start+bind.SegOffset, bind.Segment, bind.Section, bind.Dylib, bind.Name)
						}
					}
					// Dedup these symbols (has repeats but also additional symbols??)
					if m.DyldExportsTrie() != nil && m.DyldExportsTrie().Size > 0 && verbose {
						fmt.Printf("\nDyld Exports\n")
						fmt.Println("------------")
						exports, err := m.DyldExports()
						if err != nil {
							return err
						}
						for _, export := range exports {
							if export.Flags.ReExport() {
								export.FoundInDylib = m.ImportedLibraries()[export.Other-1]
								reimg, err := f.Image(export.FoundInDylib)
								if err != nil {
									return err
								}
								if rexpSym, err := reimg.GetExport(export.ReExport); err == nil {
									export.Address = rexpSym.Address
								}
							}
							if doDemangle {
								if strings.HasPrefix(export.Name, "_$s") || strings.HasPrefix(export.Name, "$s") { // TODO: better detect swift symbols
									export.Name, _ = swift.Demangle(export.Name)
								} else {
									export.Name = demangle.Do(export.Name, false, false)
								}
							}
							fmt.Println(export)
						}
					}
					println()
				}

				if showStrings {
					if options != onlyStrings {
						fmt.Println("STRINGS")
						fmt.Println("=======")
					}
					cstrs, err := m.GetCStrings()
					if err != nil {
						return fmt.Errorf("failed to get strings: %v", err)
					}
					for sec, strs := range cstrs {
						fmt.Printf("\n[%s]\n", sec)
						fmt.Println(strings.Repeat("-", len(sec)) + "--")
						for s, pos := range strs {
							fmt.Printf("%s: %s\n", symAddrColor("%#09x", pos), symNameColor(fmt.Sprintf("%#v", s)))
						}
					}

					if cfstrs, err := m.GetCFStrings(); err == nil {
						if len(cfstrs) > 0 {
							fmt.Printf("\nCFStrings\n")
							fmt.Println("---------")
							for _, cfstr := range cfstrs {
								fmt.Printf("%s:  %s\n", symAddrColor("%#09x", cfstr.Address), symNameColor(fmt.Sprintf("%#v", cfstr.Name)))
							}
						}
					}

					if m.HasSwift() {
						if ss, err := mcmd.FindSwiftStrings(m); err == nil {
							if len(ss) > 0 {
								fmt.Printf("\nSwift Strings\n")
								fmt.Println("-------------")
							}
							// sort by address
							addrs := make([]uint64, 0, len(ss))
							for addr := range ss {
								addrs = append(addrs, addr)
							}
							slices.Sort(addrs)
							for _, addr := range addrs {
								fmt.Printf("%s:  %s\n", symAddrColor("%#09x", addr), symNameColor(fmt.Sprintf("%#v", ss[addr])))
							}
						}
					}
					println()
				}

				if showStubs {
					if options != onlyStubs {
						fmt.Printf("\nStubs\n")
						fmt.Println("=====")
					}
					if err := image.Analyze(); err != nil {
						log.WithError(err).Warn("failed to analyze image")
					}
					for stubAddr, addr := range image.Analysis.SymbolStubs {
						if symName, ok := f.AddressToSymbol[addr]; ok {
							fmt.Printf("%#x => %#x: %s\n", stubAddr, addr, symName)
						}
					}
					println()
				}

				if len(searchPattern) > 0 {
					var run string
					var gadget [][]byte

					patternBytes := strings.Fields(searchPattern) // split on whitespace

					for idx, abyte := range patternBytes {
						if abyte == "*" {
							if len(run) > 0 { // got a wildcard, but you were building a run
								pattern, err := hex.DecodeString(run)
								if err != nil {
									return fmt.Errorf("failed to decode pattern '%s': %v", run, err)
								}
								// add the run to the gadget list
								gadget = append(gadget, pattern)
								// zero out the run
								run = ""
							}
							gadget = append(gadget, []byte{}) // add a wildcard to the gadget as empty array
						} else {
							run += abyte
							if idx == len(patternBytes)-1 { // last byte
								pattern, err := hex.DecodeString(run)
								if err != nil {
									return fmt.Errorf("failed to decode pattern '%s': %v", run, err)
								}
								// add the run to the gadget list
								gadget = append(gadget, pattern)
							}
						}
					}

					if !dumpALL || options != onlySearch {
						fmt.Printf("\nSearch Results\n")
						fmt.Println("--------------")
					}

					if textSeg := m.Segment("__TEXT"); textSeg != nil {
						uuid, off, err := f.GetOffset(textSeg.Addr)
						if err != nil {
							return fmt.Errorf("failed to get offset for %s: %v", textSeg.Name, err)
						}
						data, err := f.ReadBytesForUUID(uuid, int64(off), textSeg.Filesz)
						if err != nil {
							return fmt.Errorf("failed to read cstrings in %s: %v", textSeg.Name, err)
						}

						i := 0
						found := 0
						foundOffset := uint64(0)

						done := func() {
							foundPattern = true
							if dumpALL {
								fmt.Printf("%#x\t%s\n", textSeg.Addr+foundOffset, image.Name)
							} else {
								fmt.Printf("%#x\n", textSeg.Addr+foundOffset)
							}
						}

						for found >= 0 && i < len(data) { // stop if not found
							foundFirstPart := false
							for idx, gad := range gadget {
								if len(gad) == 0 { //  wildcards
									if foundFirstPart && idx == len(gadget)-1 { // last wildcard after found; DONE
										done()
									}
									i++
								} else if found = bytes.Index(data[i:], gad); foundFirstPart && found == 0 { // found next part of pattern
									if idx == len(gadget)-1 { // last part of pattern; DONE
										done()
									}
									i += len(gad)
								} else if !foundFirstPart && found >= 0 {
									if idx == 0 { // found first part of pattern
										foundFirstPart = true
										foundOffset = uint64(i + found)
									}
									if len(gadget) == 1 { // only one part of pattern; DONE
										done()
									}
									i += found + len(gad)
								} else if found < 0 { // pattern broken or not found
									i += len(gad)
									break
								}
							}
						}
					}
				}
				// sacrifice to the GC gods (TODO: still not good enough)
				m = nil
				image = nil
			}

			if len(searchPattern) > 0 && !foundPattern {
				return fmt.Errorf("pattern '%s' not found", searchPattern)
			}

		} else {
			log.Error("you must supply a dylib MachO to parse")
		}

		return nil
	},
}
