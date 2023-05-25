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
package dyld

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	swift "github.com/blacktop/ipsw/internal/swift"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DyldCmd.AddCommand(dyldSearchCmd)

	dyldSearchCmd.Flags().StringP("load-command", "l", "", "Search for specific load command regex")
	dyldSearchCmd.Flags().StringP("protocol", "p", "", "Search for specific ObjC protocol regex")
	dyldSearchCmd.Flags().StringP("class", "c", "", "Search for specific ObjC class regex")
	dyldSearchCmd.Flags().StringP("category", "g", "", "Search for specific ObjC category regex")
	dyldSearchCmd.Flags().StringP("sel", "s", "", "Search for specific ObjC selector regex")
	dyldSearchCmd.Flags().String("ivar", "", "Search for specific ObjC instance variable regex")
	viper.BindPFlag("dyld.search.load-command", dyldSearchCmd.Flags().Lookup("load-command"))
	viper.BindPFlag("dyld.search.protocol", dyldSearchCmd.Flags().Lookup("protocol"))
	viper.BindPFlag("dyld.search.class", dyldSearchCmd.Flags().Lookup("class"))
	viper.BindPFlag("dyld.search.category", dyldSearchCmd.Flags().Lookup("category"))
	viper.BindPFlag("dyld.search.sel", dyldSearchCmd.Flags().Lookup("sel"))
	viper.BindPFlag("dyld.search.ivar", dyldSearchCmd.Flags().Lookup("ivar"))
	dyldSearchCmd.MarkFlagsMutuallyExclusive("protocol", "class", "category", "sel", "ivar")
}

// dyldSearchCmd represents the search command
var dyldSearchCmd = &cobra.Command{
	Use:           "search",
	Aliases:       []string{"sr"},
	Short:         "Find Dylib files for given search criteria",
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		if viper.GetString("dyld.search.load-command") == "" &&
			viper.GetString("dyld.search.protocol") == "" &&
			viper.GetString("dyld.search.class") == "" &&
			viper.GetString("dyld.search.category") == "" &&
			viper.GetString("dyld.search.sel") == "" &&
			viper.GetString("dyld.search.ivar") == "" {
			return fmt.Errorf("must specify a search criteria via one of the flags")
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
			return fmt.Errorf("failed to open dyld shared cache %s: %w", dscPath, err)
		}

		for _, img := range f.Images {
			m, err := img.GetMacho()
			if err != nil {
				return err
			}
			if viper.GetString("dyld.search.load-command") != "" {
				re, err := regexp.Compile(viper.GetString("dyld.search.load-command"))
				if err != nil {
					return fmt.Errorf("invalid regex '%s': %w", viper.GetString("dyld.search.load-command"), err)
				}
				for _, lc := range m.Loads {
					if re.MatchString(lc.Command().String()) {
						fmt.Printf("%s\t%s=%s\n", colorImage(filepath.Base(img.Name)), colorField("load"), lc.Command())
						break
					}
				}
			}
			if viper.GetString("dyld.search.sym") != "" {
				symRE, err := regexp.Compile(viper.GetString("dyld.search.sym"))
				if err != nil {
					return fmt.Errorf("invalid regex '%s': %w", viper.GetString("dyld.search.sym"), err)
				}
				for _, sym := range m.Symtab.Syms {
					if symRE.MatchString(sym.Name) {
						fmt.Printf("%#x: %s\t(%s)\t%s\n", sym.Value, filepath.Base(img.Name), sym.Type.String(""), sym.Name)
						break
					}
				}
				if binds, err := m.GetBindInfo(); err == nil {
					for _, bind := range binds {
						if symRE.MatchString(bind.Name) {
							fmt.Printf("%#x: %s\t(%s)\n", bind.Start+bind.Offset, filepath.Base(img.Name), bind.Name)
							break
						}
					}
				}
				if exports, err := m.GetExports(); err == nil {
					for _, export := range exports {
						if symRE.MatchString(export.Name) {
							fmt.Printf("%#x: %s\t(%s)\t%s\n", export.Address, filepath.Base(img.Name), export.Flags, export.Name)
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
							fmt.Printf("%#x: %s\t(%s)\t%s\n", export.Address, filepath.Base(img.Name), export.Flags, export.Name)
							break
						}
					}
				}
			}
			if m.HasObjC() {
				if viper.GetString("dyld.search.protocol") != "" {
					if protos, err := m.GetObjCProtocols(); err == nil {
						protRE, err := regexp.Compile(viper.GetString("dyld.search.protocol"))
						if err != nil {
							return fmt.Errorf("invalid regex '%s': %w", viper.GetString("dyld.search.protocol"), err)
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
								fmt.Printf("%s\t%s=%s\n", colorImage(img.Name), colorField("protocol"), ps[0])
							} else {
								fmt.Printf("%s\t%s=%v\n", colorImage(img.Name), colorField("protocols"), ps)
							}
						}
						// check for subprotocols
						seen := make(map[uint64]bool)
						for _, proto := range protos {
							for _, sub := range proto.Prots {
								if protRE.MatchString(sub.Name) {
									if _, yes := seen[proto.Ptr]; !yes {
										fmt.Printf("    %s: %s\t%s=%s\t%s=%s\n", colorAddr("%#09x", proto.Ptr), filepath.Base(img.Name), colorField("protocol"), proto.Name, colorField("sub-protocol"), sub.Name)
										seen[proto.Ptr] = true
									}
								}
							}
						}
					} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
						log.Error(err.Error())
					}
				}
				if viper.GetString("dyld.search.class") != "" || viper.GetString("dyld.search.protocol") != "" || viper.GetString("dyld.search.sel") != "" || viper.GetString("dyld.search.ivar") != "" {
					if classes, err := m.GetObjCClasses(); err == nil {
						classRE, err := regexp.Compile(viper.GetString("dyld.search.class"))
						if err != nil {
							return fmt.Errorf("invalid regex '%s': %w", viper.GetString("dyld.search.class"), err)
						}
						for _, class := range classes {
							if viper.GetString("dyld.search.class") != "" && classRE.MatchString(class.Name) {
								fmt.Printf("%s: %s\n", colorAddr("%#09x", class.ClassPtr), filepath.Base(img.Name))
								break
							}
							if viper.GetString("dyld.search.protocol") != "" {
								protRE, err := regexp.Compile(viper.GetString("dyld.search.protocol"))
								if err != nil {
									return fmt.Errorf("invalid regex '%s': %w", viper.GetString("dyld.search.protocol"), err)
								}
								for _, proto := range class.Protocols {
									if protRE.MatchString(proto.Name) {
										fmt.Printf("    %s: %s\t%s=%s\t%s=%s\n", colorAddr("%#09x", class.ClassPtr), filepath.Base(img.Name), colorField("protocol"), proto.Name, colorField("class"), swift.DemangleBlob(class.Name))
										break
									} else { // check for subprotocols
										for _, sub := range proto.Prots {
											if protRE.MatchString(sub.Name) {
												fmt.Printf("    %s: %s\t%s=%s\t%s=%s\t%s=%s\n", colorAddr("%#09x", class.ClassPtr), filepath.Base(img.Name), colorField("protocol"), proto.Name, colorField("sub-protocol"), sub.Name, colorField("class"), swift.DemangleBlob(class.Name))
												break
											}
										}
									}
								}
							}
							if viper.GetString("dyld.search.sel") != "" {
								re, err := regexp.Compile(viper.GetString("dyld.search.sel"))
								if err != nil {
									return fmt.Errorf("invalid regex '%s': %w", viper.GetString("dyld.search.sel"), err)
								}
								for _, sel := range class.ClassMethods {
									if re.MatchString(sel.Name) {
										fmt.Printf("%s: %s\t%s=%s %s=%s\n", colorAddr("%#09x", sel.ImpVMAddr), filepath.Base(img.Name), colorField("class"), class.Name, colorField("sel"), sel.Name)
										break
									}
								}
								for _, sel := range class.InstanceMethods {
									if re.MatchString(sel.Name) {
										fmt.Printf("%s: %s\t%s=%s %s=%s\n", colorAddr("%#09x", sel.ImpVMAddr), filepath.Base(img.Name), colorField("class"), class.Name, colorField("sel"), sel.Name)
										break
									}
								}
							}
							if viper.GetString("dyld.search.ivar") != "" {
								ivarRE, err := regexp.Compile(viper.GetString("dyld.search.ivar"))
								if err != nil {
									return fmt.Errorf("invalid regex '%s': %w", viper.GetString("dyld.search.ivar"), err)
								}
								for _, ivar := range class.Ivars {
									if ivarRE.MatchString(ivar.Name) {
										fmt.Printf("%s\t%s=%s %s=%s\n", colorImage(filepath.Base(img.Name)), colorField("class"), class.Name, colorField("ivar"), ivar.Name)
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
			if viper.GetString("dyld.search.category") != "" || viper.GetString("dyld.search.class") != "" || viper.GetString("dyld.search.protocol") != "" || viper.GetString("dyld.search.sel") != "" || viper.GetString("dyld.search.ivar") != "" {
				if cats, err := m.GetObjCCategories(); err == nil {
					catRE, err := regexp.Compile(viper.GetString("dyld.search.category"))
					if err != nil {
						return fmt.Errorf("invalid regex '%s': %w", viper.GetString("dyld.search.category"), err)
					}
					for _, cat := range cats {
						if viper.GetString("dyld.search.category") != "" && catRE.MatchString(cat.Name) {
							fmt.Printf("%s: %s\n", colorAddr("%#09x", cat.VMAddr), filepath.Base(img.Name))
							break
						}
						if viper.GetString("dyld.search.class") != "" {
							classRE, err := regexp.Compile(viper.GetString("dyld.search.class"))
							if err != nil {
								return fmt.Errorf("invalid regex '%s': %w", viper.GetString("dyld.search.class"), err)
							}
							if classRE.MatchString(cat.Class.Name) {
								fmt.Printf("%s: %s\n", colorAddr("%#09x", cat.Class.ClassPtr), filepath.Base(img.Name))
							}
						}
						if viper.GetString("dyld.search.protocol") != "" {
							protRE, err := regexp.Compile(viper.GetString("dyld.search.protocol"))
							if err != nil {
								return fmt.Errorf("invalid regex '%s': %w", viper.GetString("dyld.search.protocol"), err)
							}
							for _, proto := range cat.Protocols {
								if protRE.MatchString(proto.Name) {
									fmt.Printf("    %s: %s\t%s=%s\t%s=%s\t%s=%s\n", colorAddr("%#09x", cat.Class.ClassPtr), filepath.Base(img.Name), colorField("protocol"), proto.Name, colorField("category"), swift.DemangleBlob(cat.Name), colorField("class"), swift.DemangleBlob(cat.Class.Name))
									break
								} else { // check for subprotocols
									for _, sub := range proto.Prots {
										if protRE.MatchString(sub.Name) {
											fmt.Printf("    %s: %s\t%s=%s\t%s=%s\t%s=%s\t%s=%s\n", colorAddr("%#09x", cat.Class.ClassPtr), filepath.Base(img.Name), colorField("protocol"), proto.Name, colorField("sub-protocol"), sub.Name, colorField("category"), swift.DemangleBlob(cat.Name), colorField("class"), swift.DemangleBlob(cat.Class.Name))
											break
										}
									}
								}
							}
							for _, proto := range cat.Class.Protocols {
								if protRE.MatchString(proto.Name) {
									fmt.Printf("    %s: %s\t%s=%s\t%s=%s\t%s=%s\n", colorAddr("%#09x", cat.Class.ClassPtr), filepath.Base(img.Name), colorField("protocol"), proto.Name, colorField("category"), swift.DemangleBlob(cat.Name), colorField("class"), swift.DemangleBlob(cat.Class.Name))
									break
								} else { // check for subprotocols
									for _, sub := range proto.Prots {
										if protRE.MatchString(sub.Name) {
											fmt.Printf("    %s: %s\t%s=%s\t%s=%s\t%s=%s\t%s=%s\n", colorAddr("%#09x", cat.Class.ClassPtr), filepath.Base(img.Name), colorField("protocol"), proto.Name, colorField("sub-protocol"), sub.Name, colorField("category"), swift.DemangleBlob(cat.Name), colorField("class"), swift.DemangleBlob(cat.Class.Name))
											break
										}
									}
								}
							}
						}
						if viper.GetString("dyld.search.sel") != "" {
							re, err := regexp.Compile(viper.GetString("dyld.search.sel"))
							if err != nil {
								return fmt.Errorf("invalid regex '%s': %w", viper.GetString("dyld.search.sel"), err)
							}
							for _, sel := range cat.Class.ClassMethods {
								if re.MatchString(sel.Name) {
									fmt.Printf("%s: %s\t%s=%s %s=%s %s=%s\n", colorAddr("%#09x", sel.ImpVMAddr), filepath.Base(img.Name), colorField("cat"), cat.Name, colorField("class"), cat.Class.Name, colorField("sel"), sel.Name)
									break
								}
							}
							for _, sel := range cat.Class.InstanceMethods {
								if re.MatchString(sel.Name) {
									fmt.Printf("%s: %s\t%s=%s %s=%s %s=%s\n", colorAddr("%#09x", sel.ImpVMAddr), filepath.Base(img.Name), colorField("cat"), cat.Name, colorField("class"), cat.Class.Name, colorField("sel"), sel.Name)
									break
								}
							}
						}
						if viper.GetString("dyld.search.ivar") != "" {
							ivarRE, err := regexp.Compile(viper.GetString("dyld.search.ivar"))
							if err != nil {
								return fmt.Errorf("invalid regex '%s': %w", viper.GetString("dyld.search.ivar"), err)
							}
							for _, ivar := range cat.Class.Ivars {
								if ivarRE.MatchString(ivar.Name) {
									fmt.Printf("%s\t%s=%s %s=%s %s=%s\n", colorImage(img.Name), colorField("cat"), cat.Name, colorField("class"), cat.Class.Name, colorField("ivar"), ivar.Name)
									break
								}
							}
						}
					}
				} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
					log.Error(err.Error())
				}
			}
			if viper.GetString("dyld.search.sel") != "" {
				selRE, err := regexp.Compile(viper.GetString("dyld.search.sel"))
				if err != nil {
					return fmt.Errorf("invalid regex '%s': %w", viper.GetString("dyld.search.sel"), err)
				}
				if sels, err := m.GetObjCSelectorReferences(); err == nil {
					for ref, sel := range sels {
						if selRE.MatchString(sel.Name) {
							fmt.Printf("%s: %s\t%s=%s %s=%s\n", colorImage(filepath.Base(img.Name)), colorAddr("%#09x", ref), colorField("addr"), colorAddr("%#09x", sel.VMAddr), colorField("sel"), sel.Name)
						}
					}
				} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
					log.Error(err.Error())
				}
			}
		}

		return nil
	},
}
