/*
Copyright © 2018-2023 blacktop

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
	"cmp"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/alecthomas/chroma/v2/quick"
	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-macho/types/objc"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/demangle"
	swift "github.com/blacktop/ipsw/internal/swift"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/fatih/color"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/exp/slices"
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
}

// MachoCmd represents the macho command
var MachoCmd = &cobra.Command{
	Use:     "macho <DSC> <DYLIB>",
	Aliases: []string{"m"},
	Short:   "Parse an incache dylib file",
	Args:    cobra.ExactArgs(2),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) == 1 {
			return getImages(args[0]), cobra.ShellCompDirectiveDefault
		}
		return getDSCs(toComplete), cobra.ShellCompDirectiveDefault
	},
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// flags
		verbose := viper.GetBool("verbose")
		color := viper.GetBool("color")
		showLoadCommands, _ := cmd.Flags().GetBool("loads")
		showLoadCommandsAsJSON, _ := cmd.Flags().GetBool("json")
		showObjC, _ := cmd.Flags().GetBool("objc")
		showObjcRefs, _ := cmd.Flags().GetBool("objc-refs")
		showSwift, _ := cmd.Flags().GetBool("swift")
		showSwiftAll, _ := cmd.Flags().GetBool("swift-all")
		dumpSymbols, _ := cmd.Flags().GetBool("symbols")
		doDemangle, _ := cmd.Flags().GetBool("demangle")
		showFuncStarts, _ := cmd.Flags().GetBool("starts")
		dumpStrings, _ := cmd.Flags().GetBool("strings")
		dumpStubs, _ := cmd.Flags().GetBool("stubs")
		searchPattern, _ := cmd.Flags().GetString("search")
		dumpALL, _ := cmd.Flags().GetBool("all")
		extractDylib, _ := cmd.Flags().GetBool("extract")
		extractPath, _ := cmd.Flags().GetString("output")
		forceExtract, _ := cmd.Flags().GetBool("force")
		// validate flags
		onlyFuncStarts := !showLoadCommands && !showObjC && !showSwift && !dumpStubs && showFuncStarts
		onlyStubs := !showLoadCommands && !showObjC && !showSwift && !showFuncStarts && dumpStubs
		onlySearch := !showLoadCommands && !showObjC && !showSwift && !showFuncStarts && !dumpStubs && searchPattern != ""
		onlySwift := !showLoadCommands && !showObjC && !showFuncStarts && !dumpStubs && searchPattern == "" && showSwift
		if doDemangle && (!dumpSymbols && !showSwift) {
			return fmt.Errorf("you must also supply --symbols OR --swift flag to demangle")
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

				if showLoadCommands || !showObjC && !dumpSymbols && !dumpStrings && !showFuncStarts && !dumpStubs && searchPattern == "" && !showSwift {
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
					fmt.Println("Objective-C")
					fmt.Println("===========")
					if m.HasObjC() {
						if info, err := m.GetObjCImageInfo(); err == nil {
							fmt.Println(info.Flags)
						} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
							log.Error(err.Error())
						}
						if verbose {
							fmt.Println(m.GetObjCToc())
						}
						if protos, err := m.GetObjCProtocols(); err == nil {
							slices.SortStableFunc(protos, func(a, b objc.Protocol) int {
								return cmp.Compare(a.Name, b.Name)
							})
							seen := make(map[uint64]bool)
							for _, proto := range protos {
								if _, ok := seen[proto.Ptr]; !ok { // prevent displaying duplicates
									if verbose {
										if color {
											quick.Highlight(os.Stdout, swift.DemangleBlob(proto.Verbose()), "objc", "terminal256", "nord")
											quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "objc", "terminal256", "nord")
										} else {
											fmt.Println(swift.DemangleBlob(proto.Verbose()))
										}
									} else {
										if color {
											quick.Highlight(os.Stdout, proto.String()+"\n", "objc", "terminal256", "nord")
										} else {
											fmt.Println(proto.String())
										}
									}
									seen[proto.Ptr] = true
								}
							}
						} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
							log.Error(err.Error())
						}
						if classes, err := m.GetObjCClasses(); err == nil {
							slices.SortStableFunc(classes, func(a, b objc.Class) int {
								return cmp.Compare(a.Name, b.Name)
							})
							for _, class := range classes {
								if verbose {
									if color {
										quick.Highlight(os.Stdout, swift.DemangleBlob(class.Verbose()), "objc", "terminal256", "nord")
										quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "objc", "terminal256", "nord")
									} else {
										fmt.Println(swift.DemangleBlob(class.Verbose()))
									}
								} else {
									if color {
										quick.Highlight(os.Stdout, class.String()+"\n", "objc", "terminal256", "nord")
									} else {
										fmt.Println(class.String())
									}
								}
							}
						} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
							log.Error(err.Error())
						}
						if cats, err := m.GetObjCCategories(); err == nil {
							slices.SortStableFunc(cats, func(a, b objc.Category) int {
								return cmp.Compare(a.Name, b.Name)
							})
							for _, cat := range cats {
								if verbose {
									if color {
										quick.Highlight(os.Stdout, swift.DemangleBlob(cat.Verbose()), "objc", "terminal256", "nord")
										quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "objc", "terminal256", "nord")
									} else {
										fmt.Println(swift.DemangleBlob(cat.Verbose()))
									}
								} else {
									if color {
										quick.Highlight(os.Stdout, cat.String()+"\n", "objc", "terminal256", "nord")
									} else {
										fmt.Println(cat.String())
									}
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
									// if verbose {
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
							if verbose {
								if classes, err := m.GetObjCClassNames(); err == nil {
									fmt.Printf("\n@objc_classname\n")
									for vmaddr, className := range classes {
										fmt.Printf("0x%011x: %s\n", vmaddr, className)
									}
								} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
									log.Error(err.Error())
								}
								if methods, err := m.GetObjCMethodNames(); err == nil {
									fmt.Printf("\n@objc_methname\n")
									for vmaddr, method := range methods {
										fmt.Printf("0x%011x: %s\n", vmaddr, method)
									}
								} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
									log.Error(err.Error())
								}
							}
						}

					} else {
						fmt.Println("  - no objc")
					}
					fmt.Println()
				}

				fixedLocals := false

				if showSwift {
					if !onlySwift {
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
						toc := m.GetSwiftTOC()
						if err := m.PreCache(); err != nil { // cache fields and types
							log.Errorf("failed to precache swift fields/types for %s: %v", filepath.Base(image.Name), err)
						}
						var sout string
						if typs, err := m.GetSwiftTypes(); err == nil {
							if verbose {
								if color {
									quick.Highlight(os.Stdout, "/********\n* TYPES *\n********/\n\n", "swift", "terminal256", "nord")
								} else {
									fmt.Println("TYPES")
									fmt.Print("-----\n\n")
								}
							}
							for i, typ := range typs {
								if verbose {
									sout = typ.Verbose()
									if doDemangle {
										sout = swift.DemangleBlob(sout)
									}
								} else {
									sout = typ.String()
									if doDemangle {
										sout = swift.DemangleSimpleBlob(typ.String())
									}
								}
								if color {
									quick.Highlight(os.Stdout, sout+"\n", "swift", "terminal256", "nord")
									if i < (toc.Types-1) && (toc.Protocols > 0 || toc.ProtocolConformances > 0) { // skip last type if others follow
										quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "swift", "terminal256", "nord")
									} else {
										fmt.Println()
									}
								} else {
									fmt.Println(sout + "\n")
								}
							}
						} else if !errors.Is(err, macho.ErrSwiftSectionError) {
							log.Errorf("failed to parse swift types for %s: %v", filepath.Base(image.Name), err)
						}
						if protos, err := m.GetSwiftProtocols(); err == nil {
							if verbose {
								if color {
									quick.Highlight(os.Stdout, "/************\n* PROTOCOLS *\n************/\n\n", "swift", "terminal256", "nord")
								} else {
									fmt.Println("PROTOCOLS")
									fmt.Print("---------\n\n")
								}
							}
							for i, proto := range protos {
								if verbose {
									sout = proto.Verbose()
									if doDemangle {
										sout = swift.DemangleBlob(sout)
									}
								} else {
									sout = proto.String()
									if doDemangle {
										sout = swift.DemangleSimpleBlob(proto.String())
									}
								}
								if color {
									quick.Highlight(os.Stdout, sout+"\n", "swift", "terminal256", "nord")
									if i < (toc.Protocols-1) && toc.ProtocolConformances > 0 { // skip last type if others follow
										quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "swift", "terminal256", "nord")
									} else {
										fmt.Println()
									}
								} else {
									fmt.Println(sout + "\n")
								}
							}
						} else if !errors.Is(err, macho.ErrSwiftSectionError) {
							log.Errorf("failed to parse swift protocols for %s: %v", filepath.Base(image.Name), err)
						}
						if protos, err := m.GetSwiftProtocolConformances(); err == nil {
							if verbose {
								if color {
									quick.Highlight(os.Stdout, "/************************\n* PROTOCOL CONFORMANCES *\n************************/\n\n", "swift", "terminal256", "nord")
								} else {
									fmt.Println("PROTOCOL CONFORMANCES")
									fmt.Print("---------------------\n\n")
								}
							}
							for i, proto := range protos {
								if verbose {
									sout = proto.Verbose()
									if doDemangle {
										sout = swift.DemangleBlob(sout)
									}
								} else {
									sout = proto.String()
									if doDemangle {
										sout = swift.DemangleSimpleBlob(proto.String())
									}
								}
								if color {
									quick.Highlight(os.Stdout, sout+"\n", "swift", "terminal256", "nord")
									if i < (toc.ProtocolConformances - 1) { // skip last type if others follow
										quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "swift", "terminal256", "nord")
									} else {
										fmt.Println()
									}
								} else {
									fmt.Println(sout + "\n")
								}
							}
						} else if !errors.Is(err, macho.ErrSwiftSectionError) {
							log.Errorf("failed to parse swift protocol conformances for %s: %v", filepath.Base(image.Name), err)
						}
						if asstyps, err := m.GetSwiftAssociatedTypes(); err == nil {
							if verbose {
								if color {
									quick.Highlight(os.Stdout, "/*******************\n* ASSOCIATED TYPES *\n*******************/\n\n", "swift", "terminal256", "nord")
								} else {
									fmt.Println("ASSOCIATED TYPES")
									fmt.Print("---------------------\n\n")
								}
							}
							for _, at := range asstyps {
								if verbose {
									sout = at.Verbose()
									if doDemangle {
										sout = swift.DemangleBlob(sout)
									}
								} else {
									sout = at.String()
									if doDemangle {
										sout = swift.DemangleSimpleBlob(at.String())
									}
								}
								if color {
									quick.Highlight(os.Stdout, sout+"\n", "swift", "terminal256", "nord")
									quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "swift", "terminal256", "nord")
								} else {
									fmt.Println(sout + "\n")
								}
							}
						} else if !errors.Is(err, macho.ErrSwiftSectionError) {
							log.Errorf("failed to parse swift associated types for %s: %v", filepath.Base(image.Name), err)
						}
						if showSwiftAll {
							fmt.Println("Swift (Other Sections)")
							fmt.Println("======================")
							fmt.Println()
							if entry, err := m.GetSwiftEntry(); err == nil {
								log.WithFields(log.Fields{
									"segment": "__TEXT",
									"section": "__swift5_entry",
								}).Info("Swift Entry")
								fmt.Println()
								fmt.Printf("%#x: entry\n\n", entry)
							} else if !errors.Is(err, macho.ErrSwiftSectionError) {
								log.Errorf("failed to parse swift entrypoint for %s: %v", filepath.Base(image.Name), err)
							}
							if bins, err := m.GetSwiftBuiltinTypes(); err == nil {
								log.WithFields(log.Fields{
									"segment": "__TEXT",
									"section": "__swift5_builtin",
								}).Info("Swift Builtin Types")
								fmt.Println()
								for _, bin := range bins {
									if verbose {
										sout = bin.Verbose()
										if doDemangle {
											sout = swift.DemangleBlob(sout)
										}
									} else {
										sout = bin.String()
										if doDemangle {
											sout = swift.DemangleSimpleBlob(bin.String())
										}
									}
									if color {
										quick.Highlight(os.Stdout, sout+"\n", "swift", "terminal256", "nord")
										quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "swift", "terminal256", "nord")
									} else {
										fmt.Println(sout + "\n")
									}
								}
							} else if !errors.Is(err, macho.ErrSwiftSectionError) {
								log.Errorf("failed to parse swift built-in types for %s: %v", filepath.Base(image.Name), err)
							}
							if metadatas, err := m.GetSwiftColocateMetadata(); err == nil {
								log.WithFields(log.Fields{
									"segment": "__TEXT",
									"section": "__textg_swiftm",
								}).Info("Swift Colocate Metadata")
								fmt.Println()
								for _, md := range metadatas {
									fmt.Println(md.Verbose())
								}
							} else if !errors.Is(err, macho.ErrSwiftSectionError) {
								log.Errorf("failed to parse swift colocate metadata for %s: %v", filepath.Base(image.Name), err)
							}
							if mpenums, err := m.GetSwiftMultiPayloadEnums(); err == nil {
								log.WithFields(log.Fields{
									"segment": "__TEXT",
									"section": "__swift5_mpenum",
								}).Info("Swift MultiPayload Enums")
								fmt.Println()
								for _, mpenum := range mpenums {
									sout = mpenum.String()
									if doDemangle {
										sout = swift.DemangleSimpleBlob(mpenum.String())
									}
									if color {
										quick.Highlight(os.Stdout, sout+"\n", "swift", "terminal256", "nord")
										quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "swift", "terminal256", "nord")
									} else {
										fmt.Println(sout + "\n")
									}
								}
							} else if !errors.Is(err, macho.ErrSwiftSectionError) {
								log.Errorf("failed to parse swift multi-payload enums for %s: %v", filepath.Base(image.Name), err)
							}
							if closures, err := m.GetSwiftClosures(); err == nil {
								log.WithFields(log.Fields{
									"segment": "__TEXT",
									"section": "__swift5_capture",
								}).Info("Swift Closures")
								fmt.Println()
								for _, closure := range closures {
									sout = closure.String()
									if doDemangle {
										sout = swift.DemangleSimpleBlob(closure.String())
									}
									if color {
										quick.Highlight(os.Stdout, sout+"\n", "swift", "terminal256", "nord")
										quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "swift", "terminal256", "nord")
									} else {
										fmt.Println(sout + "\n")
									}
								}
							} else if !errors.Is(err, macho.ErrSwiftSectionError) {
								log.Errorf("failed to parse swift closures for %s: %v", filepath.Base(image.Name), err)
							}
							if rep, err := m.GetSwiftDynamicReplacementInfo(); err == nil {
								log.WithFields(log.Fields{
									"segment": "__TEXT",
									"section": "__swift5_replace",
								}).Info("Swift Dynamic Replacement Info")
								fmt.Println()
								if rep != nil {
									fmt.Println(rep)
								}
							} else if !errors.Is(err, macho.ErrSwiftSectionError) {
								log.Errorf("failed to parse swift dynamic replacement info for %s: %v", filepath.Base(image.Name), err)
							}
							if rep, err := m.GetSwiftDynamicReplacementInfoForOpaqueTypes(); err == nil {
								log.WithFields(log.Fields{
									"segment": "__TEXT",
									"section": "__swift5_replac2",
								}).Info("Swift Dynamic Replacement Info For Opaque Types")
								fmt.Println()
								if rep != nil {
									fmt.Println(rep)
								}
							} else if !errors.Is(err, macho.ErrSwiftSectionError) {
								log.Errorf("failed to parse swift dynamic replacement info opaque types for %s: %v", filepath.Base(image.Name), err)
							}
							if afuncs, err := m.GetSwiftAccessibleFunctions(); err == nil {
								log.WithFields(log.Fields{
									"segment": "__TEXT",
									"section": "__swift5_acfuncs",
								}).Info("Swift Accessible Functions")
								fmt.Println()
								for _, afunc := range afuncs {
									fmt.Println(afunc)
								}
							} else if !errors.Is(err, macho.ErrSwiftSectionError) {
								log.Errorf("failed to parse swift accessible functions for %s: %v", filepath.Base(image.Name), err)
							}
						}
					} else {
						fmt.Println("  - no swift")
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
							if verbose {
								fmt.Printf("%#016x-%#016x\n", fn.StartAddr, fn.EndAddr)
							} else {
								fmt.Printf("0x%016X\n", fn.StartAddr)
							}
						}
					}
				}

				if dumpSymbols {
					image.ParseLocalSymbols(false)
					w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
					if m.Symtab != nil {
						fmt.Println("SYMBOLS")
						fmt.Println("=======")
						undeflush := false
						for _, sym := range m.Symtab.Syms {
							if sym.Type.IsUndefinedSym() && !undeflush {
								w.Flush()
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
								fmt.Fprintf(w, "              %s\n", strings.Join([]string{symTypeColor(sym.GetType(m)), symNameColor(sym.Name), symLibColor(sym.GetLib(m))}, "\t"))
							} else {
								fmt.Fprintf(w, "%s:  %s\n", symAddrColor("%#09x", sym.Value), strings.Join([]string{symTypeColor(sym.GetType(m)), symNameColor(sym.Name), symLibColor(sym.GetLib(m))}, "\t"))
							}
						}
						w.Flush()
					}
					if binds, err := m.GetBindInfo(); err == nil {
						fmt.Printf("\nDyld Binds\n")
						fmt.Println("----------")
						for _, bind := range binds {
							if doDemangle {
								bind.Name, _ = swift.Demangle(bind.Name)
							}
							fmt.Fprintf(w, "%#09x:\t(%s.%s|from %s)\t%s\n", bind.Start+bind.Offset, bind.Segment, bind.Section, bind.Dylib, bind.Name)
						}
						w.Flush()
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
				}

				if dumpStrings {
					fmt.Printf("\nCStrings\n")
					fmt.Println("--------")
					for _, sec := range m.Sections {
						if sec.Flags.IsCstringLiterals() || sec.Seg == "__TEXT" && sec.Name == "__const" {
							uuid, off, err := f.GetOffset(sec.Addr)
							if err != nil {
								return fmt.Errorf("failed to get offset for %s.%s: %v", sec.Seg, sec.Name, err)
							}
							dat, err := f.ReadBytesForUUID(uuid, int64(off), sec.Size)
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

								s = strings.Trim(s, "\x00")

								if len(s) > 0 {
									if (sec.Seg == "__TEXT" && sec.Name == "__const") && !utils.IsASCII(s) {
										continue // skip non-ascii strings when dumping __TEXT.__const
									}
									fmt.Printf("%#x: %#v\n", pos, s)
								}
							}
						}
					}

					if cfstrs, err := m.GetCFStrings(); err == nil {
						if len(cfstrs) > 0 {
							fmt.Printf("\nCFStrings\n")
							fmt.Println("---------")
							for _, cfstr := range cfstrs {
								fmt.Printf("%#09x:  %#v\n", cfstr.Address, cfstr.Name)
							}
						}
					}

					if info, err := m.GetObjCImageInfo(); err == nil {
						if info != nil && info.HasSwift() {
							if ss, err := mcmd.FindSwiftStrings(m); err == nil {
								if len(ss) > 0 {
									fmt.Printf("\nSwift Strings\n")
									fmt.Println("-------------")
								}
								for addr, s := range ss {
									fmt.Printf("%s:  %s\n", symAddrColor("%#09x", addr), symNameColor(fmt.Sprintf("%#v", s)))
								}
							}
						}
					}
				}

				if dumpStubs {
					if !onlyStubs {
						fmt.Printf("\nStubs\n")
						fmt.Println("=====")
					}
					if err := image.Analyze(); err != nil {
						return err
					}
					for stubAddr, addr := range image.Analysis.SymbolStubs {
						if symName, ok := f.AddressToSymbol[addr]; ok {
							fmt.Printf("%#x => %#x: %s\n", stubAddr, addr, symName)
						}
					}
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

					if !dumpALL || !onlySearch {
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
									i += 1
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
