/*
Copyright © 2025 blacktop

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
package macho

import (
	"fmt"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/codesign/types"
	"github.com/blacktop/go-macho/pkg/swift"
	"github.com/blacktop/go-macho/types/objc"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/colors"
	"github.com/blacktop/ipsw/internal/search"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func recurseProtocols(re *regexp.Regexp, proto objc.Protocol, depth int) (bool, string, int) {
	if re.MatchString(proto.Name) {
		return true, proto.Name, depth
	}
	for _, sub := range proto.Prots {
		if found, name, newDepth := recurseProtocols(re, sub, depth+1); found {
			return true, name, newDepth
		}
	}
	return false, "", 0
}

var colorAddr = colors.Faint().SprintfFunc()
var colorImage = colors.BoldHiMagenta().SprintFunc()
var colorField = colors.BoldHiBlue().SprintFunc()

func init() {
	MachoCmd.AddCommand(machoSearchCmd)
	machoSearchCmd.Flags().StringP("load-command", "l", "", "Search for specific load command regex")
	machoSearchCmd.Flags().StringP("launch-const", "t", "", "Search for launch constraint regex")
	machoSearchCmd.Flags().StringP("import", "i", "", "Search for specific import regex")
	machoSearchCmd.Flags().StringP("section", "x", "", "Search for specific section regex")
	machoSearchCmd.Flags().StringP("uuid", "u", "", "Search for MachO by UUID")
	machoSearchCmd.Flags().StringP("sym", "m", "", "Search for specific symbol regex")
	machoSearchCmd.Flags().StringP("protocol", "p", "", "Search for specific ObjC protocol regex")
	machoSearchCmd.Flags().StringP("class", "c", "", "Search for specific ObjC class regex")
	machoSearchCmd.Flags().StringP("category", "g", "", "Search for specific ObjC category regex")
	machoSearchCmd.Flags().StringP("sel", "s", "", "Search for specific ObjC selector regex")
	machoSearchCmd.Flags().StringP("ivar", "r", "", "Search for specific ObjC instance variable regex")
	machoSearchCmd.Flags().Bool("mte", false, "Search for binaries with MTE (Memory Tagging Extension) instructions")
	machoSearchCmd.Flags().String("pem-db", "", "AEA pem DB JSON file")
	machoSearchCmd.RegisterFlagCompletionFunc("ipsw", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"ipsw"}, cobra.ShellCompDirectiveFilterFileExt
	})
	machoSearchCmd.MarkFlagsMutuallyExclusive("protocol", "class", "category", "sel", "ivar")
	viper.BindPFlag("macho.search.load-command", machoSearchCmd.Flags().Lookup("load-command"))
	viper.BindPFlag("macho.search.launch-const", machoSearchCmd.Flags().Lookup("launch-const"))
	viper.BindPFlag("macho.search.import", machoSearchCmd.Flags().Lookup("import"))
	viper.BindPFlag("macho.search.section", machoSearchCmd.Flags().Lookup("section"))
	viper.BindPFlag("macho.search.uuid", machoSearchCmd.Flags().Lookup("uuid"))
	viper.BindPFlag("macho.search.sym", machoSearchCmd.Flags().Lookup("sym"))
	viper.BindPFlag("macho.search.protocol", machoSearchCmd.Flags().Lookup("protocol"))
	viper.BindPFlag("macho.search.class", machoSearchCmd.Flags().Lookup("class"))
	viper.BindPFlag("macho.search.category", machoSearchCmd.Flags().Lookup("category"))
	viper.BindPFlag("macho.search.sel", machoSearchCmd.Flags().Lookup("sel"))
	viper.BindPFlag("macho.search.ivar", machoSearchCmd.Flags().Lookup("ivar"))
	viper.BindPFlag("macho.search.mte", machoSearchCmd.Flags().Lookup("mte"))
	viper.BindPFlag("macho.search.pem-db", machoSearchCmd.Flags().Lookup("pem-db"))
}

// machoSearchCmd represents the search command
var machoSearchCmd = &cobra.Command{
	Use:           "search <IPSW>",
	Aliases:       []string{"sr"},
	Short:         "Find Mach-O files for given search criteria",
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		// flags
		loadCmdReStr := viper.GetString("macho.search.load-command")
		launchConstReStr := viper.GetString("macho.search.launch-const")
		importReStr := viper.GetString("macho.search.import")
		sectionReStr := viper.GetString("macho.search.section")
		uuidStr := viper.GetString("macho.search.uuid")
		symReStr := viper.GetString("macho.search.sym")
		protoReStr := viper.GetString("macho.search.protocol")
		classReStr := viper.GetString("macho.search.class")
		categoryReStr := viper.GetString("macho.search.category")
		selReStr := viper.GetString("macho.search.sel")
		ivarReStr := viper.GetString("macho.search.ivar")
		searchMTE := viper.GetBool("macho.search.mte")
		// validate flags
		if loadCmdReStr == "" &&
			launchConstReStr == "" &&
			importReStr == "" &&
			sectionReStr == "" &&
			uuidStr == "" &&
			symReStr == "" &&
			protoReStr == "" &&
			classReStr == "" &&
			categoryReStr == "" &&
			selReStr == "" &&
			ivarReStr == "" &&
			!searchMTE {
			return errors.New("you must specify a search criteria via one of the flags")
		}

		if searchMTE {
			return mcmd.RunMTEScanIPSW(filepath.Clean(args[0]), viper.GetString("macho.search.pem-db"))
		}

		if err := search.ForEachMachoInIPSW(filepath.Clean(args[0]), viper.GetString("macho.search.pem-db"), func(path string, m *macho.File) error {
			if loadCmdReStr != "" {
				re, err := regexp.Compile(loadCmdReStr)
				if err != nil {
					return fmt.Errorf("invalid regex '%s': %w", loadCmdReStr, err)
				}
				for _, lc := range m.Loads {
					if re.MatchString(lc.Command().String()) {
						fmt.Printf("%s\t%s=%s\n", colorImage(path), colorField("load"), lc.Command())
						fmt.Printf("\t%s\n", lc)
						break
					}
				}
			}
			if launchConstReStr != "" {
				if m.CodeSignature() != nil {
					re, err := regexp.Compile(launchConstReStr)
					if err != nil {
						return fmt.Errorf("invalid regex '%s': %w", launchConstReStr, err)
					}
					if len(m.CodeSignature().LaunchConstraintsSelf) > 0 {
						lc, err := types.ParseLaunchContraints(m.CodeSignature().LaunchConstraintsSelf)
						if err != nil {
							return err
						}
						for k, v := range lc.Requirements {
							if re.MatchString(k) || v == reflect.String && re.MatchString(v.(string)) {
								fmt.Printf("%s\t%s={%s:%v}\n", colorImage(path), colorField("launch-const(self)"), k, v)
								break
							}
						}
					}
					if len(m.CodeSignature().LaunchConstraintsParent) > 0 {
						lc, err := types.ParseLaunchContraints(m.CodeSignature().LaunchConstraintsParent)
						if err != nil {
							return err
						}
						for k, v := range lc.Requirements {
							if re.MatchString(k) || v == reflect.String && re.MatchString(v.(string)) {
								fmt.Printf("%s\t%s=(%s:%s)\n", colorImage(path), colorField("launch-const(parent)"), k, v)
								break
							}
						}
					}
					if len(m.CodeSignature().LaunchConstraintsResponsible) > 0 {
						lc, err := types.ParseLaunchContraints(m.CodeSignature().LaunchConstraintsResponsible)
						if err != nil {
							return err
						}
						for k, v := range lc.Requirements {
							if re.MatchString(k) || v == reflect.String && re.MatchString(v.(string)) {
								fmt.Printf("%s\t%s=(%s:%s)\n", colorImage(path), colorField("launch-const(parent)"), k, v)
								break
							}
						}
					}
					if len(m.CodeSignature().LibraryConstraints) > 0 {
						lc, err := types.ParseLaunchContraints(m.CodeSignature().LibraryConstraints)
						if err != nil {
							return err
						}
						for k, v := range lc.Requirements {
							if re.MatchString(k) || v == reflect.String && re.MatchString(v.(string)) {
								fmt.Printf("%s\t%s=(%s:%s)\n", colorImage(path), colorField("library-const"), k, v)
								break
							}
						}
					}
				}
			}
			if importReStr != "" {
				re, err := regexp.Compile(importReStr)
				if err != nil {
					return fmt.Errorf("invalid regex '%s': %w", importReStr, err)
				}
				for _, imp := range m.ImportedLibraries() {
					if re.MatchString(imp) {
						fmt.Printf("%s\t%s=%s\n", colorImage(path), colorField("import"), imp)
						break
					}
				}
			}
			if sectionReStr != "" {
				re, err := regexp.Compile(sectionReStr)
				if err != nil {
					return fmt.Errorf("invalid regex '%s': %w", sectionReStr, err)
				}
				for _, sec := range m.Sections {
					if re.MatchString(fmt.Sprintf("%s.%s", sec.Seg, sec.Name)) {
						fmt.Printf("%s\t%s=%s\n", colorImage(path), colorField("load"), fmt.Sprintf("%s.%s", sec.Seg, sec.Name))
						break
					}
				}
			}
			if uuidStr != "" {
				if m.UUID() != nil && strings.EqualFold(m.UUID().UUID.String(), uuidStr) {
					fmt.Printf("%s\t%s=%s\n", colorImage(path), colorField("uuid"), uuidStr)
				}
			}
			if symReStr != "" {
				symRE, err := regexp.Compile(symReStr)
				if err != nil {
					return fmt.Errorf("invalid regex '%s': %w", symReStr, err)
				}
				if m.Symtab != nil {
					for _, sym := range m.Symtab.Syms {
						if symRE.MatchString(sym.Name) {
							fmt.Printf("%#x: %s\t(%s)\t%s\n", sym.Value, colorImage(path), sym.Type.String(""), sym.Name)
							break
						}
					}
				}
				if binds, err := m.GetBindInfo(); err == nil {
					for _, bind := range binds {
						if symRE.MatchString(bind.Name) {
							fmt.Printf("%#x: %s\t(%s)\n", bind.Start+bind.SegOffset, colorImage(path), bind.Name)
							break
						}
					}
				}
				if exports, err := m.GetExports(); err == nil {
					for _, export := range exports {
						if symRE.MatchString(export.Name) {
							fmt.Printf("%#x: %s\t(%s)\t%s\n", export.Address, colorImage(path), export.Flags, export.Name)
							break
						}
					}
				}
				if m.DyldExportsTrie() != nil && m.DyldExportsTrie().Size > 0 {
					exports, err := m.DyldExports()
					if err != nil {
						return err
					}
					for _, export := range exports {
						if symRE.MatchString(export.Name) {
							fmt.Printf("%#x: %s\t(%s)\t%s\n", export.Address, colorImage(path), export.Flags, export.Name)
							break
						}
					}
				}
			}
			if m.HasObjC() {
				if protoReStr != "" {
					if protos, err := m.GetObjCProtocols(); err == nil {
						protRE, err := regexp.Compile(protoReStr)
						if err != nil {
							return fmt.Errorf("invalid regex '%s': %w", protoReStr, err)
						}
						var ps []string
						for _, proto := range protos {
							if protRE.MatchString(proto.Name) {
								ps = append(ps, proto.Name)
							} else { // check for subprotocols
								for _, sub := range proto.Prots {
									if found, name, _ := recurseProtocols(protRE, sub, 1); found {
										ps = append(ps, name)
									}
								}
							}
						}
						ps = utils.Unique(ps)
						if len(ps) > 0 {
							if len(ps) == 1 {
								fmt.Printf("%s\t%s=%s\n", colorImage(path), colorField("protocol"), ps[0])
							} else {
								fmt.Printf("%s\t%s=%v\n", colorImage(path), colorField("protocols"), ps)
							}
						}
						// check for subprotocols
						seen := make(map[uint64]bool)
						for _, proto := range protos {
							for _, sub := range proto.Prots {
								if found, name, depth := recurseProtocols(protRE, sub, 1); found {
									if _, yes := seen[proto.Ptr]; !yes {
										if depth > 1 {
											fmt.Printf("    %s: %s\t%s=%s\t%s=%s %s=%d\n", colorAddr("%#09x", proto.Ptr), filepath.Base(path), colorField("protocol"), proto.Name, colorField("sub-protocol"), name, colorField("depth"), depth)
										} else {
											fmt.Printf("    %s: %s\t%s=%s\t%s=%s\n", colorAddr("%#09x", proto.Ptr), filepath.Base(path), colorField("protocol"), proto.Name, colorField("sub-protocol"), name)
										}
										seen[proto.Ptr] = true
									}
								}
							}
						}
					} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
						log.Error(err.Error())
					}
				}
				if classReStr != "" || protoReStr != "" || selReStr != "" || ivarReStr != "" {
					if classes, err := m.GetObjCClasses(); err == nil {
						classRE, err := regexp.Compile(classReStr)
						if err != nil {
							return fmt.Errorf("invalid regex '%s': %w", classReStr, err)
						}
						for _, class := range classes {
							classType := "class"
							if class.IsSwift() {
								classType = colorField("swift_class")
							}
							if classReStr != "" && classRE.MatchString(class.Name) {
								fmt.Printf("%s: %s\t%s=%s\n", colorAddr("%#09x", class.ClassPtr), filepath.Base(path), colorField(classType), swift.DemangleBlob(class.Name))
							}
							if protoReStr != "" {
								protRE, err := regexp.Compile(protoReStr)
								if err != nil {
									return fmt.Errorf("invalid regex '%s': %w", protoReStr, err)
								}
								for _, proto := range class.Protocols {
									if protRE.MatchString(proto.Name) {
										fmt.Printf("    %s: %s\t%s=%s\t%s=%s\n", colorAddr("%#09x", class.ClassPtr), filepath.Base(path), colorField("protocol"), proto.Name, colorField(classType), swift.DemangleBlob(class.Name))
										break
									}
									// check for subprotocols
									for _, sub := range proto.Prots {
										if found, name, depth := recurseProtocols(protRE, sub, 1); found {
											if depth > 1 {
												fmt.Printf("    %s: %s\t%s=%s\t%s=%s %s=%d\t%s=%s\n", colorAddr("%#09x", class.ClassPtr), filepath.Base(path), colorField("protocol"), proto.Name, colorField("sub-protocol"), name, colorField("depth"), depth, colorField(classType), swift.DemangleBlob(class.Name))
											} else {
												fmt.Printf("    %s: %s\t%s=%s\t%s=%s\t%s=%s\n", colorAddr("%#09x", class.ClassPtr), filepath.Base(path), colorField("protocol"), proto.Name, colorField("sub-protocol"), name, colorField(classType), swift.DemangleBlob(class.Name))
											}
											break
										}
									}
								}
							}
							if selReStr != "" {
								re, err := regexp.Compile(selReStr)
								if err != nil {
									return fmt.Errorf("invalid regex '%s': %w", selReStr, err)
								}
								for _, sel := range class.ClassMethods {
									if re.MatchString(sel.Name) {
										fmt.Printf("%s: %s\t%s=%s %s=%s\n", colorAddr("%#09x", sel.ImpVMAddr), filepath.Base(path), colorField(classType), class.Name, colorField("sel"), sel.Name)
										break
									}
								}
								for _, sel := range class.InstanceMethods {
									if re.MatchString(sel.Name) {
										fmt.Printf("%s: %s\t%s=%s %s=%s\n", colorAddr("%#09x", sel.ImpVMAddr), filepath.Base(path), colorField(classType), class.Name, colorField("sel"), sel.Name)
										break
									}
								}
							}
							if ivarReStr != "" {
								ivarRE, err := regexp.Compile(ivarReStr)
								if err != nil {
									return fmt.Errorf("invalid regex '%s': %w", ivarReStr, err)
								}
								for _, ivar := range class.Ivars {
									if ivarRE.MatchString(ivar.Name) {
										fmt.Printf("%s\t%s=%s %s=%s\n", colorImage(path), colorField(classType), class.Name, colorField("ivar"), ivar.Name)
										break
									}
								}
							}
						}
					} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
						log.Error(fmt.Sprintf("%s: %s", path, err.Error()))
					}
				}
				if categoryReStr != "" || classReStr != "" || protoReStr != "" || selReStr != "" || ivarReStr != "" {
					if cats, err := m.GetObjCCategories(); err == nil {
						catRE, err := regexp.Compile(categoryReStr)
						if err != nil {
							return fmt.Errorf("invalid regex '%s': %w", categoryReStr, err)
						}
						for _, cat := range cats {
							if categoryReStr != "" && catRE.MatchString(cat.Name) {
								fmt.Printf("%#x: %s\n", colorAddr("%#09x", cat.VMAddr), path)
								break
							}
							if classReStr != "" {
								classRE, err := regexp.Compile(classReStr)
								if err != nil {
									return fmt.Errorf("invalid regex '%s': %w", classReStr, err)
								}
								if classRE.MatchString(cat.Class.Name) {
									fmt.Printf("%s: %s\t%s=%s\t%s=%s\n", colorAddr("%#09x", cat.Class.ClassPtr), filepath.Base(path), colorField("category"), swift.DemangleBlob(cat.Name), colorField("class"), swift.DemangleBlob(cat.Class.Name))
								}
							}
							classType := "class"
							if cat.Class.IsSwift() {
								classType = colorField("swift_class")
							}
							if protoReStr != "" {
								protRE, err := regexp.Compile(protoReStr)
								if err != nil {
									return fmt.Errorf("invalid regex '%s': %w", protoReStr, err)
								}
								for _, proto := range cat.Protocols {
									if protRE.MatchString(proto.Name) {
										fmt.Printf("    %s: %s\t%s=%s\t%s=%s\t%s=%s\n", colorAddr("%#09x", cat.Class.ClassPtr), filepath.Base(path), colorField("protocol"), proto.Name, colorField("category"), swift.DemangleBlob(cat.Name), colorField(classType), swift.DemangleBlob(cat.Class.Name))
										break
									}
									// check for subprotocols
									for _, sub := range proto.Prots {
										if found, name, depth := recurseProtocols(protRE, sub, 1); found {
											if depth > 1 {
												fmt.Printf("    %s: %s\t%s=%s\t%s=%s %s=%d\t%s=%s\t%s=%s\n", colorAddr("%#09x", cat.Class.ClassPtr), filepath.Base(path), colorField("protocol"), proto.Name, colorField("sub-protocol"), name, colorField("depth"), depth, colorField("category"), swift.DemangleBlob(cat.Name), colorField(classType), swift.DemangleBlob(cat.Class.Name))
											} else {
												fmt.Printf("    %s: %s\t%s=%s\t%s=%s\t%s=%s\t%s=%s\n", colorAddr("%#09x", cat.Class.ClassPtr), filepath.Base(path), colorField("protocol"), proto.Name, colorField("sub-protocol"), name, colorField("category"), swift.DemangleBlob(cat.Name), colorField(classType), swift.DemangleBlob(cat.Class.Name))
											}
											break
										}
									}
								}
								for _, proto := range cat.Class.Protocols {
									if protRE.MatchString(proto.Name) {
										fmt.Printf("    %s: %s\t%s=%s\t%s=%s\t%s=%s\n", colorAddr("%#09x", cat.Class.ClassPtr), filepath.Base(path), colorField("protocol"), proto.Name, colorField("category"), swift.DemangleBlob(cat.Name), colorField(classType), swift.DemangleBlob(cat.Class.Name))
										break
									}
									// check for subprotocols
									for _, sub := range proto.Prots {
										if found, name, depth := recurseProtocols(protRE, sub, 1); found {
											if depth > 1 {
												fmt.Printf("    %s: %s\t%s=%s\t%s=%s %s=%d\t%s=%s\t%s=%s\n", colorAddr("%#09x", cat.Class.ClassPtr), filepath.Base(path), colorField("protocol"), proto.Name, colorField("sub-protocol"), name, colorField("depth"), depth, colorField("category"), swift.DemangleBlob(cat.Name), colorField(classType), swift.DemangleBlob(cat.Class.Name))
											} else {
												fmt.Printf("    %s: %s\t%s=%s\t%s=%s\t%s=%s\t%s=%s\n", colorAddr("%#09x", cat.Class.ClassPtr), filepath.Base(path), colorField("protocol"), proto.Name, colorField("sub-protocol"), name, colorField("category"), swift.DemangleBlob(cat.Name), colorField(classType), swift.DemangleBlob(cat.Class.Name))
											}
											break
										}
									}
								}
							}
							if selReStr != "" {
								re, err := regexp.Compile(selReStr)
								if err != nil {
									return fmt.Errorf("invalid regex '%s': %w", selReStr, err)
								}
								for _, sel := range cat.Class.ClassMethods {
									if re.MatchString(sel.Name) {
										fmt.Printf("%s: %s\t%s=%s %s=%s %s=%s\n", colorAddr("%#09x", sel.ImpVMAddr), filepath.Base(path), colorField("cat"), cat.Name, colorField(classType), cat.Class.Name, colorField("sel"), sel.Name)
										break
									}
								}
								for _, sel := range cat.Class.InstanceMethods {
									if re.MatchString(sel.Name) {
										fmt.Printf("%s: %s\t%s=%s %s=%s %s=%s\n", colorAddr("%#09x", sel.ImpVMAddr), filepath.Base(path), colorField("cat"), cat.Name, colorField(classType), cat.Class.Name, colorField("sel"), sel.Name)
										break
									}
								}
							}
							if ivarReStr != "" {
								ivarRE, err := regexp.Compile(ivarReStr)
								if err != nil {
									return fmt.Errorf("invalid regex '%s': %w", ivarReStr, err)
								}
								for _, ivar := range cat.Class.Ivars {
									if ivarRE.MatchString(ivar.Name) {
										fmt.Printf("%s\t%s=%s %s=%s %s=%s\n", colorImage(path), colorField("cat"), cat.Name, colorField(classType), cat.Class.Name, colorField("ivar"), ivar.Name)
										break
									}
								}
							}
						}
					} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
						log.Error(err.Error())
					}
				}
				if selReStr != "" {
					selRE, err := regexp.Compile(selReStr)
					if err != nil {
						return fmt.Errorf("invalid regex '%s': %w", selReStr, err)
					}
					if sels, err := m.GetObjCSelectorReferences(); err == nil {
						for ref, sel := range sels {
							if selRE.MatchString(sel.Name) {
								fmt.Printf("%s: %s\t%s=%s %s=%s\n", colorImage(path), colorAddr("%#09x", ref), colorField("addr"), colorAddr("%#09x", sel.VMAddr), colorField("sel"), sel.Name)
							}
						}
					} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
						log.Error(err.Error())
					}
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("failed to scan files in IPSW: %v", err)
		}

		return nil
	},
}
