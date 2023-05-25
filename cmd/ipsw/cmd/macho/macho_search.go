/*
Copyright © 2023 blacktop

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
	"regexp"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/search"
	swift "github.com/blacktop/ipsw/internal/swift"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/fatih/color"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var colorAddr = color.New(color.Faint).SprintfFunc()
var colorImage = color.New(color.Bold, color.FgHiMagenta).SprintFunc()
var colorField = color.New(color.Bold, color.FgHiBlue).SprintFunc()

func init() {
	MachoCmd.AddCommand(machoSearchCmd)
	machoSearchCmd.Flags().StringP("load-command", "l", "", "Search for specific load command regex")
	machoSearchCmd.Flags().StringP("section", "x", "", "Search for specific section regex")
	machoSearchCmd.Flags().StringP("sym", "m", "", "Search for specific symbol regex")
	machoSearchCmd.Flags().StringP("protocol", "p", "", "Search for specific ObjC protocol regex")
	machoSearchCmd.Flags().StringP("class", "c", "", "Search for specific ObjC class regex")
	machoSearchCmd.Flags().StringP("category", "g", "", "Search for specific ObjC category regex")
	machoSearchCmd.Flags().StringP("sel", "s", "", "Search for specific ObjC selector regex")
	machoSearchCmd.Flags().StringP("ivar", "r", "", "Search for specific ObjC instance variable regex")
	machoSearchCmd.RegisterFlagCompletionFunc("ipsw", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"ipsw"}, cobra.ShellCompDirectiveFilterFileExt
	})
	machoSearchCmd.MarkFlagsMutuallyExclusive("protocol", "class", "category", "sel", "ivar")
	viper.BindPFlag("macho.search.load-command", machoSearchCmd.Flags().Lookup("load-command"))
	viper.BindPFlag("macho.search.section", machoSearchCmd.Flags().Lookup("section"))
	viper.BindPFlag("macho.search.sym", machoSearchCmd.Flags().Lookup("sym"))
	viper.BindPFlag("macho.search.protocol", machoSearchCmd.Flags().Lookup("protocol"))
	viper.BindPFlag("macho.search.class", machoSearchCmd.Flags().Lookup("class"))
	viper.BindPFlag("macho.search.category", machoSearchCmd.Flags().Lookup("category"))
	viper.BindPFlag("macho.search.sel", machoSearchCmd.Flags().Lookup("sel"))
	viper.BindPFlag("macho.search.ivar", machoSearchCmd.Flags().Lookup("ivar"))
}

// machoSearchCmd represents the search command
var machoSearchCmd = &cobra.Command{
	Use:           "search <IPSW>",
	Aliases:       []string{"sr"},
	Short:         "Find Mach-O files for given search criteria",
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		if viper.GetString("macho.search.load-command") == "" &&
			viper.GetString("macho.search.section") == "" &&
			viper.GetString("macho.search.sym") == "" &&
			viper.GetString("macho.search.protocol") == "" &&
			viper.GetString("macho.search.class") == "" &&
			viper.GetString("macho.search.category") == "" &&
			viper.GetString("macho.search.sel") == "" &&
			viper.GetString("macho.search.ivar") == "" {
			return errors.New("you must specify a search criteria via one of the flags")
		}

		if err := search.ForEachMachoInIPSW(filepath.Clean(args[0]), func(path string, m *macho.File) error {
			if viper.GetString("macho.search.load-command") != "" {
				re, err := regexp.Compile(viper.GetString("macho.search.load-command"))
				if err != nil {
					return fmt.Errorf("invalid regex '%s': %w", viper.GetString("macho.search.load-command"), err)
				}
				for _, lc := range m.Loads {
					if re.MatchString(lc.Command().String()) {
						fmt.Printf("%s\t%s=%s\n", colorImage(path), colorField("load"), lc.Command())
						break
					}
				}
			}
			if viper.GetString("macho.search.section") != "" {
				re, err := regexp.Compile(viper.GetString("macho.search.section"))
				if err != nil {
					return fmt.Errorf("invalid regex '%s': %w", viper.GetString("macho.search.section"), err)
				}
				for _, sec := range m.Sections {
					if re.MatchString(fmt.Sprintf("%s.%s", sec.Seg, sec.Name)) {
						fmt.Printf("%s\t%s=%s\n", colorImage(path), colorField("load"), fmt.Sprintf("%s.%s", sec.Seg, sec.Name))
						break
					}
				}
			}
			if viper.GetString("macho.search.sym") != "" {
				symRE, err := regexp.Compile(viper.GetString("macho.search.sym"))
				if err != nil {
					return fmt.Errorf("invalid regex '%s': %w", viper.GetString("macho.search.sym"), err)
				}
				for _, sym := range m.Symtab.Syms {
					if symRE.MatchString(sym.Name) {
						fmt.Printf("%#x: %s\t(%s)\t%s\n", sym.Value, colorImage(path), sym.Type.String(""), sym.Name)
						break
					}
				}
				if binds, err := m.GetBindInfo(); err == nil {
					for _, bind := range binds {
						if symRE.MatchString(bind.Name) {
							fmt.Printf("%#x: %s\t(%s)\n", bind.Start+bind.Offset, colorImage(path), bind.Name)
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
				if viper.GetString("macho.search.protocol") != "" {
					if protos, err := m.GetObjCProtocols(); err == nil {
						protRE, err := regexp.Compile(viper.GetString("macho.search.protocol"))
						if err != nil {
							return fmt.Errorf("invalid regex '%s': %w", viper.GetString("macho.search.protocol"), err)
						}
						var ps []string
						for _, proto := range protos {
							if protRE.MatchString(proto.Name) {
								ps = append(ps, proto.Name)
							} else { // check for subprotocols
								for _, sub := range proto.Prots {
									if protRE.MatchString(sub.Name) {
										ps = append(ps, sub.Name)
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
								if protRE.MatchString(sub.Name) {
									if _, yes := seen[proto.Ptr]; !yes {
										fmt.Printf("    %s: %s\t%s=%s\t%s=%s\n", colorAddr("%#09x", proto.Ptr), filepath.Base(path), colorField("protocol"), proto.Name, colorField("sub-protocol"), sub.Name)
										seen[proto.Ptr] = true
									}
								}
							}
						}
					} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
						log.Error(err.Error())
					}
				}
				if viper.GetString("macho.search.class") != "" || viper.GetString("macho.search.protocol") != "" || viper.GetString("macho.search.sel") != "" || viper.GetString("macho.search.ivar") != "" {
					if classes, err := m.GetObjCClasses(); err == nil {
						classRE, err := regexp.Compile(viper.GetString("macho.search.class"))
						if err != nil {
							return fmt.Errorf("invalid regex '%s': %w", viper.GetString("macho.search.class"), err)
						}
						for _, class := range classes {
							if viper.GetString("macho.search.class") != "" && classRE.MatchString(class.Name) {
								fmt.Printf("%s: %s\n", colorAddr("%#09x", class.ClassPtr), filepath.Base(path))
								break
							}
							if viper.GetString("macho.search.protocol") != "" {
								protRE, err := regexp.Compile(viper.GetString("macho.search.protocol"))
								if err != nil {
									return fmt.Errorf("invalid regex '%s': %w", viper.GetString("macho.search.protocol"), err)
								}
								for _, proto := range class.Protocols {
									if protRE.MatchString(proto.Name) {
										fmt.Printf("    %s: %s\t%s=%s\t%s=%s\n", colorAddr("%#09x", class.ClassPtr), filepath.Base(path), colorField("protocol"), proto.Name, colorField("class"), swift.DemangleBlob(class.Name))
										break
									} else { // check for subprotocols
										for _, sub := range proto.Prots {
											if protRE.MatchString(sub.Name) {
												fmt.Printf("    %s: %s\t%s=%s\t%s=%s\t%s=%s\n", colorAddr("%#09x", class.ClassPtr), filepath.Base(path), colorField("protocol"), proto.Name, colorField("sub-protocol"), sub.Name, colorField("class"), swift.DemangleBlob(class.Name))
												break
											}
										}
									}
								}
							}
							if viper.GetString("macho.search.sel") != "" {
								re, err := regexp.Compile(viper.GetString("macho.search.sel"))
								if err != nil {
									return fmt.Errorf("invalid regex '%s': %w", viper.GetString("macho.search.sel"), err)
								}
								for _, sel := range class.ClassMethods {
									if re.MatchString(sel.Name) {
										fmt.Printf("%s: %s\t%s=%s %s=%s\n", colorAddr("%#09x", sel.ImpVMAddr), filepath.Base(path), colorField("class"), class.Name, colorField("sel"), sel.Name)
										break
									}
								}
								for _, sel := range class.InstanceMethods {
									if re.MatchString(sel.Name) {
										fmt.Printf("%s: %s\t%s=%s %s=%s\n", colorAddr("%#09x", sel.ImpVMAddr), filepath.Base(path), colorField("class"), class.Name, colorField("sel"), sel.Name)
										break
									}
								}
							}
							if viper.GetString("macho.search.ivar") != "" {
								ivarRE, err := regexp.Compile(viper.GetString("macho.search.ivar"))
								if err != nil {
									return fmt.Errorf("invalid regex '%s': %w", viper.GetString("macho.search.ivar"), err)
								}
								for _, ivar := range class.Ivars {
									if ivarRE.MatchString(ivar.Name) {
										fmt.Printf("%s\t%s=%s %s=%s\n", colorImage(path), colorField("class"), class.Name, colorField("ivar"), ivar.Name)
										break
									}
								}
							}
						}
					} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
						log.Error(err.Error())
					}
				}
			}
			if viper.GetString("macho.search.category") != "" || viper.GetString("macho.search.class") != "" || viper.GetString("macho.search.protocol") != "" || viper.GetString("macho.search.sel") != "" || viper.GetString("macho.search.ivar") != "" {
				if cats, err := m.GetObjCCategories(); err == nil {
					catRE, err := regexp.Compile(viper.GetString("macho.search.category"))
					if err != nil {
						return fmt.Errorf("invalid regex '%s': %w", viper.GetString("macho.search.category"), err)
					}
					for _, cat := range cats {
						if viper.GetString("macho.search.category") != "" && catRE.MatchString(cat.Name) {
							fmt.Printf("%#x: %s\n", colorAddr("%#09x", cat.VMAddr), path)
							break
						}
						if viper.GetString("macho.search.class") != "" {
							classRE, err := regexp.Compile(viper.GetString("macho.search.class"))
							if err != nil {
								return fmt.Errorf("invalid regex '%s': %w", viper.GetString("macho.search.class"), err)
							}
							if classRE.MatchString(cat.Class.Name) {
								fmt.Printf("%s: %s\n", colorAddr("%#09x", cat.Class.ClassPtr), filepath.Base(path))
							}
						}
						if viper.GetString("macho.search.protocol") != "" {
							protRE, err := regexp.Compile(viper.GetString("macho.search.protocol"))
							if err != nil {
								return fmt.Errorf("invalid regex '%s': %w", viper.GetString("macho.search.protocol"), err)
							}
							for _, proto := range cat.Protocols {
								if protRE.MatchString(proto.Name) {
									fmt.Printf("    %s: %s\t%s=%s\t%s=%s\t%s=%s\n", colorAddr("%#09x", cat.Class.ClassPtr), filepath.Base(path), colorField("protocol"), proto.Name, colorField("category"), swift.DemangleBlob(cat.Name), colorField("class"), swift.DemangleBlob(cat.Class.Name))
									break
								} else { // check for subprotocols
									for _, sub := range proto.Prots {
										if protRE.MatchString(sub.Name) {
											fmt.Printf("    %s: %s\t%s=%s\t%s=%s\t%s=%s\t%s=%s\n", colorAddr("%#09x", cat.Class.ClassPtr), filepath.Base(path), colorField("protocol"), proto.Name, colorField("sub-protocol"), sub.Name, colorField("category"), swift.DemangleBlob(cat.Name), colorField("class"), swift.DemangleBlob(cat.Class.Name))
											break
										}
									}
								}
							}
							for _, proto := range cat.Class.Protocols {
								if protRE.MatchString(proto.Name) {
									fmt.Printf("    %s: %s\t%s=%s\t%s=%s\t%s=%s\n", colorAddr("%#09x", cat.Class.ClassPtr), filepath.Base(path), colorField("protocol"), proto.Name, colorField("category"), swift.DemangleBlob(cat.Name), colorField("class"), swift.DemangleBlob(cat.Class.Name))
									break
								} else { // check for subprotocols
									for _, sub := range proto.Prots {
										if protRE.MatchString(sub.Name) {
											fmt.Printf("    %s: %s\t%s=%s\t%s=%s\t%s=%s\t%s=%s\n", colorAddr("%#09x", cat.Class.ClassPtr), filepath.Base(path), colorField("protocol"), proto.Name, colorField("sub-protocol"), sub.Name, colorField("category"), swift.DemangleBlob(cat.Name), colorField("class"), swift.DemangleBlob(cat.Class.Name))
											break
										}
									}
								}
							}
						}
						if viper.GetString("macho.search.sel") != "" {
							re, err := regexp.Compile(viper.GetString("macho.search.sel"))
							if err != nil {
								return fmt.Errorf("invalid regex '%s': %w", viper.GetString("macho.search.sel"), err)
							}
							for _, sel := range cat.Class.ClassMethods {
								if re.MatchString(sel.Name) {
									fmt.Printf("%s: %s\t%s=%s %s=%s %s=%s\n", colorAddr("%#09x", sel.ImpVMAddr), filepath.Base(path), colorField("cat"), cat.Name, colorField("class"), cat.Class.Name, colorField("sel"), sel.Name)
									break
								}
							}
							for _, sel := range cat.Class.InstanceMethods {
								if re.MatchString(sel.Name) {
									fmt.Printf("%s: %s\t%s=%s %s=%s %s=%s\n", colorAddr("%#09x", sel.ImpVMAddr), filepath.Base(path), colorField("cat"), cat.Name, colorField("class"), cat.Class.Name, colorField("sel"), sel.Name)
									break
								}
							}
						}
						if viper.GetString("macho.search.ivar") != "" {
							ivarRE, err := regexp.Compile(viper.GetString("macho.search.ivar"))
							if err != nil {
								return fmt.Errorf("invalid regex '%s': %w", viper.GetString("macho.search.ivar"), err)
							}
							for _, ivar := range cat.Class.Ivars {
								if ivarRE.MatchString(ivar.Name) {
									fmt.Printf("%s\t%s=%s %s=%s %s=%s\n", colorImage(path), colorField("cat"), cat.Name, colorField("class"), cat.Class.Name, colorField("ivar"), ivar.Name)
									break
								}
							}
						}
					}
				} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
					log.Error(err.Error())
				}
			}
			if viper.GetString("macho.search.sel") != "" {
				selRE, err := regexp.Compile(viper.GetString("macho.search.sel"))
				if err != nil {
					return fmt.Errorf("invalid regex '%s': %w", viper.GetString("macho.search.sel"), err)
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
			return nil
		}); err != nil {
			return fmt.Errorf("failed to scan files in IPSW: %v", err)
		}

		return nil
	},
}
