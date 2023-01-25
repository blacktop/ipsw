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
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	MachoCmd.AddCommand(machoSearchCmd)
	machoSearchCmd.Flags().StringP("ipsw", "i", "", "Path to IPSW to scan for search criteria")
	machoSearchCmd.Flags().StringP("load-command", "l", "", "Search for specific load command regex")
	machoSearchCmd.Flags().StringP("protocol", "p", "", "Search for specific ObjC protocol regex")
	machoSearchCmd.Flags().StringP("sym", "m", "", "Search for specific symbol regex")
	machoSearchCmd.Flags().StringP("class", "c", "", "Search for specific ObjC class regex")
	machoSearchCmd.Flags().StringP("category", "g", "", "Search for specific ObjC category regex")
	machoSearchCmd.Flags().StringP("sel", "s", "", "Search for specific ObjC selector regex")
	machoSearchCmd.Flags().String("ivar", "", "Search for specific ObjC instance variable regex")
	machoSearchCmd.RegisterFlagCompletionFunc("ipsw", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"ipsw", "zip"}, cobra.ShellCompDirectiveFilterFileExt
	})
	viper.BindPFlag("macho.search.ipsw", machoSearchCmd.Flags().Lookup("ipsw"))
	viper.BindPFlag("macho.search.load-command", machoSearchCmd.Flags().Lookup("load-command"))
	viper.BindPFlag("macho.search.sym", machoSearchCmd.Flags().Lookup("sym"))
	viper.BindPFlag("macho.search.protocol", machoSearchCmd.Flags().Lookup("protocol"))
	viper.BindPFlag("macho.search.class", machoSearchCmd.Flags().Lookup("class"))
	viper.BindPFlag("macho.search.category", machoSearchCmd.Flags().Lookup("category"))
	viper.BindPFlag("macho.search.sel", machoSearchCmd.Flags().Lookup("sel"))
	viper.BindPFlag("macho.search.ivar", machoSearchCmd.Flags().Lookup("ivar"))
}

// machoSearchCmd represents the search command
var machoSearchCmd = &cobra.Command{
	Use:           "search",
	Aliases:       []string{"sr"},
	Short:         "Find Mach-O files for given search criteria",
	Args:          cobra.NoArgs,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		if viper.GetString("macho.search.ipsw") != "" {
			if err := search.ForEachMachoInIPSW(filepath.Clean(viper.GetString("macho.search.ipsw")), func(path string, m *macho.File) error {
				if viper.GetString("macho.search.load-command") != "" {
					re, err := regexp.Compile(viper.GetString("macho.search.load-command"))
					if err != nil {
						return fmt.Errorf("invalid regex '%s': %w", viper.GetString("macho.search.load-command"), err)
					}
					for _, lc := range m.Loads {
						if re.MatchString(lc.Command().String()) {
							fmt.Println(path)
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
							fmt.Printf("%#x: %s\t(%s)\t%s\n", sym.Value, path, sym.Type.String(""), sym.Name)
							break
						}
					}
					if binds, err := m.GetBindInfo(); err == nil {
						for _, bind := range binds {
							if symRE.MatchString(bind.Name) {
								fmt.Printf("%#x: %s\t(%s)\n", bind.Start+bind.Offset, path, bind.Name)
								break
							}
						}
					}
					if exports, err := m.GetExports(); err == nil {
						for _, export := range exports {
							if symRE.MatchString(export.Name) {
								fmt.Printf("%#x: %s\t(%s)\t%s\n", export.Address, path, export.Flags, export.Name)
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
								fmt.Printf("%#x: %s\t(%s)\t%s\n", export.Address, path, export.Flags, export.Name)
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
							for _, proto := range protos {
								if protRE.MatchString(proto.Name) {
									fmt.Println(path)
									break
								}
							}
						} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
							log.Error(err.Error())
						}
					}
					if viper.GetString("macho.search.class") != "" || viper.GetString("macho.search.sel") != "" || viper.GetString("macho.search.ivar") != "" {
						if classes, err := m.GetObjCClasses(); err == nil {
							classRE, err := regexp.Compile(viper.GetString("macho.search.class"))
							if err != nil {
								return fmt.Errorf("invalid regex '%s': %w", viper.GetString("macho.search.class"), err)
							}
							for _, class := range classes {
								if classRE.MatchString(class.Name) {
									fmt.Println(path)
									break
								}
								if viper.GetString("macho.search.sel") != "" {
									re, err := regexp.Compile(viper.GetString("macho.search.sel"))
									if err != nil {
										return fmt.Errorf("invalid regex '%s': %w", viper.GetString("macho.search.sel"), err)
									}
									for _, sel := range class.ClassMethods {
										if re.MatchString(sel.Name) {
											fmt.Printf("%#x: %s\t(%s)\n", sel.ImpVMAddr, path, class.Name)
											break
										}
									}
									for _, sel := range class.InstanceMethods {
										if re.MatchString(sel.Name) {
											fmt.Printf("%#x: %s\t(%s)\n", sel.ImpVMAddr, path, class.Name)
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
											fmt.Printf("%s\t(%s)\n", path, class.Name)
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
				if viper.GetString("macho.search.category") != "" || viper.GetString("macho.search.ivar") != "" {
					if cats, err := m.GetObjCCategories(); err == nil {
						catRE, err := regexp.Compile(viper.GetString("macho.search.category"))
						if err != nil {
							return fmt.Errorf("invalid regex '%s': %w", viper.GetString("macho.search.category"), err)
						}
						for _, cat := range cats {
							if catRE.MatchString(cat.Name) {
								fmt.Println(path)
								break
							}
							if viper.GetString("macho.search.sel") != "" {
								re, err := regexp.Compile(viper.GetString("macho.search.sel"))
								if err != nil {
									return fmt.Errorf("invalid regex '%s': %w", viper.GetString("macho.search.sel"), err)
								}
								for _, sel := range cat.Class.ClassMethods {
									if re.MatchString(sel.Name) {
										fmt.Printf("%#x: %s\t(%s)\n", sel.ImpVMAddr, path, cat.Class.Name)
										break
									}
								}
								for _, sel := range cat.Class.InstanceMethods {
									if re.MatchString(sel.Name) {
										fmt.Printf("%#x: %s\t(%s)\n", sel.ImpVMAddr, path, cat.Class.Name)
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
										fmt.Printf("%s\t(%s)\n", path, cat.Class.Name)
										break
									}
								}
							}
						}
					} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
						log.Error(err.Error())
					}
				}
				// if viper.GetString("macho.search.sel") != "" {
				// 	if sels, err := m.GetObjCSelectorReferences(); err == nil {
				// 		for _, sel := range sels {
				// 			if sel.Name == viper.GetString("macho.search.sel") {
				// 				fmt.Println(path)
				// 				break
				// 			}
				// 		}
				// 	} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
				// 		log.Error(err.Error())
				// 	}
				// }
				return nil
			}); err != nil {
				return fmt.Errorf("failed to scan files in IPSW: %v", err)
			}
		}

		return nil
	},
}
