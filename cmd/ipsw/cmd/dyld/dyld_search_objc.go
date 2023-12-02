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
	"github.com/blacktop/go-macho/types/objc"
	swift "github.com/blacktop/ipsw/internal/swift"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/fatih/color"
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

func init() {
	dyldSearchCmd.AddCommand(dyldSearchObjcCmd)

	dyldSearchObjcCmd.Flags().StringSliceP("image", "i", []string{}, "Images to search (default: all)")
	dyldSearchObjcCmd.Flags().StringP("class", "c", "", "Search for specific ObjC class regex")
	dyldSearchObjcCmd.Flags().StringP("protocol", "p", "", "Search for specific ObjC protocol regex")
	dyldSearchObjcCmd.Flags().StringP("category", "g", "", "Search for specific ObjC category regex")
	dyldSearchObjcCmd.Flags().StringP("sel", "s", "", "Search for specific ObjC selector regex")
	dyldSearchObjcCmd.Flags().String("ivar", "", "Search for specific ObjC instance variable regex")
	viper.BindPFlag("dyld.search.objc.image", dyldSearchObjcCmd.Flags().Lookup("image"))
	viper.BindPFlag("dyld.search.objc.class", dyldSearchObjcCmd.Flags().Lookup("class"))
	viper.BindPFlag("dyld.search.objc.protocol", dyldSearchObjcCmd.Flags().Lookup("protocol"))
	viper.BindPFlag("dyld.search.objc.category", dyldSearchObjcCmd.Flags().Lookup("category"))
	viper.BindPFlag("dyld.search.objc.sel", dyldSearchObjcCmd.Flags().Lookup("sel"))
	viper.BindPFlag("dyld.search.objc.ivar", dyldSearchObjcCmd.Flags().Lookup("ivar"))
	dyldSearchObjcCmd.MarkFlagsMutuallyExclusive("protocol", "class", "category", "sel", "ivar")
}

// dyldSearchObjcCmd represents the objc command
var dyldSearchObjcCmd = &cobra.Command{
	Use:     "objc <DSC>",
	Aliases: []string{"o"},
	Short:   "Find Dylib files for given ObjC search criteria",
	Args:    cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getDSCs(toComplete), cobra.ShellCompDirectiveDefault
	},
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) (err error) {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// flags
		searchImages := viper.GetStringSlice("dyld.search.objc.image")
		classReStr := viper.GetString("dyld.search.objc.class")
		protocolReStr := viper.GetString("dyld.search.objc.protocol")
		categoryReStr := viper.GetString("dyld.search.objc.category")
		selectorReStr := viper.GetString("dyld.search.objc.sel")
		ivarReStr := viper.GetString("dyld.search.objc.ivar")
		// verify flags
		if protocolReStr == "" && classReStr == "" && categoryReStr == "" && selectorReStr == "" && ivarReStr == "" {
			return fmt.Errorf("must specify a search criteria via one of the flags")
		}
		// compile regexes
		var classRE *regexp.Regexp
		if classReStr != "" {
			classRE, err = regexp.Compile(classReStr)
			if err != nil {
				return fmt.Errorf("invalid --class regex '%s': %w", classReStr, err)
			}
		}
		var protRE *regexp.Regexp
		if protocolReStr != "" {
			protRE, err = regexp.Compile(protocolReStr)
			if err != nil {
				return fmt.Errorf("invalid --protocol regex '%s': %w", protocolReStr, err)
			}
		}
		var catRE *regexp.Regexp
		if categoryReStr != "" {
			catRE, err = regexp.Compile(categoryReStr)
			if err != nil {
				return fmt.Errorf("invalid --category regex '%s': %w", categoryReStr, err)
			}
		}
		var selRE *regexp.Regexp
		if selectorReStr != "" {
			selRE, err = regexp.Compile(selectorReStr)
			if err != nil {
				return fmt.Errorf("invalid --sel regex '%s': %w", selectorReStr, err)
			}
		}
		var ivarRE *regexp.Regexp
		if ivarReStr != "" {
			ivarRE, err = regexp.Compile(ivarReStr)
			if err != nil {
				return fmt.Errorf("invalid --ivar regex '%s': %w", ivarReStr, err)
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
				return fmt.Errorf("failed to read symlink %s: %v", dscPath, err)
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

		var images []*dyld.CacheImage
		if len(searchImages) == 0 {
			images = f.Images
		} else {
			for _, img := range searchImages {
				image, err := f.Image(img)
				if err != nil {
					return fmt.Errorf("failed to find image %s in %s: %v", img, dscPath, err)
				}
				images = append(images, image)
			}
		}

		for _, img := range images {
			m, err := img.GetMacho()
			if err != nil {
				return err
			}
			if m.HasObjC() {
				if protRE != nil {
					if protos, err := m.GetObjCProtocols(); err == nil {
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
								fmt.Printf("%s\t%s=%s\n", colorImage(img.Name), colorField("protocol"), ps[0])
							} else {
								fmt.Printf("%s\t%s=%v\n", colorImage(img.Name), colorField("protocols"), ps)
							}
						}
						// check for subprotocols
						seen := make(map[uint64]bool)
						for _, proto := range protos {
							for _, sub := range proto.Prots {
								if found, name, depth := recurseProtocols(protRE, sub, 1); found {
									if _, yes := seen[proto.Ptr]; !yes {
										if depth > 1 {
											fmt.Printf("    %s: %s\t%s=%s\t%s=%s %s=%d\n", colorAddr("%#09x", proto.Ptr), filepath.Base(img.Name), colorField("protocol"), proto.Name, colorField("sub-protocol"), name, colorField("depth"), depth)
										} else {
											fmt.Printf("    %s: %s\t%s=%s\t%s=%s\n", colorAddr("%#09x", proto.Ptr), filepath.Base(img.Name), colorField("protocol"), proto.Name, colorField("sub-protocol"), name)
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
				if classRE != nil || protRE != nil || selRE != nil || ivarRE != nil {
					if classes, err := m.GetObjCClasses(); err == nil {
						for _, class := range classes {
							classType := "class"
							if class.IsSwift() {
								classType = colorField("swift_class")
							}
							if classRE != nil && classRE.MatchString(class.Name) {
								fmt.Printf("%s: %s\t%s=%s\n", colorAddr("%#09x", class.ClassPtr), filepath.Base(img.Name), colorField(classType), swift.DemangleBlob(class.Name))
							}
							if protRE != nil {
								for _, proto := range class.Protocols {
									if protRE.MatchString(proto.Name) {
										fmt.Printf("    %s: %s\t%s=%s\t%s=%s\n", colorAddr("%#09x", class.ClassPtr), filepath.Base(img.Name), colorField("protocol"), proto.Name, colorField(classType), swift.DemangleBlob(class.Name))
										break
									}
									// check for subprotocols
									for _, sub := range proto.Prots {
										if found, name, depth := recurseProtocols(protRE, sub, 1); found {
											if depth > 1 {
												fmt.Printf("    %s: %s\t%s=%s\t%s=%s %s=%d\t%s=%s\n", colorAddr("%#09x", class.ClassPtr), filepath.Base(img.Name), colorField("protocol"), proto.Name, colorField("sub-protocol"), name, colorField("depth"), depth, colorField(classType), swift.DemangleBlob(class.Name))
											} else {
												fmt.Printf("    %s: %s\t%s=%s\t%s=%s\t%s=%s\n", colorAddr("%#09x", class.ClassPtr), filepath.Base(img.Name), colorField("protocol"), proto.Name, colorField("sub-protocol"), name, colorField(classType), swift.DemangleBlob(class.Name))
											}
											break
										}
									}
								}
							}
							if selRE != nil {
								for _, sel := range class.ClassMethods {
									if selRE.MatchString(sel.Name) {
										fmt.Printf("%s: %s\t%s=%s %s=%s\n", colorAddr("%#09x", sel.ImpVMAddr), filepath.Base(img.Name), colorField(classType), class.Name, colorField("sel"), sel.Name)
										break
									}
								}
								for _, sel := range class.InstanceMethods {
									if selRE.MatchString(sel.Name) {
										fmt.Printf("%s: %s\t%s=%s %s=%s\n", colorAddr("%#09x", sel.ImpVMAddr), filepath.Base(img.Name), colorField(classType), class.Name, colorField("sel"), sel.Name)
										break
									}
								}
							}
							if ivarRE != nil {
								for _, ivar := range class.Ivars {
									if ivarRE.MatchString(ivar.Name) {
										fmt.Printf("%s\t%s=%s %s=%s\n", colorImage(filepath.Base(img.Name)), colorField(classType), class.Name, colorField("ivar"), ivar.Name)
										break
									}
								}
							}
						}
					} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
						log.Error(err.Error())
					}
				}
				if catRE != nil || classRE != nil || protRE != nil || selRE != nil || ivarRE != nil {
					if cats, err := m.GetObjCCategories(); err == nil {
						for _, cat := range cats {
							if catRE != nil && catRE.MatchString(cat.Name) {
								fmt.Printf("%s: %s\n", colorAddr("%#09x", cat.VMAddr), filepath.Base(img.Name))
								break
							}
							if classRE != nil && classRE.MatchString(cat.Class.Name) {
								fmt.Printf("%s: %s\t%s=%s\t%s=%s\n", colorAddr("%#09x", cat.Class.ClassPtr), filepath.Base(img.Name), colorField("category"), swift.DemangleBlob(cat.Name), colorField("class"), swift.DemangleBlob(cat.Class.Name))
							}
							classType := "class"
							if cat.Class.IsSwift() {
								classType = colorField("swift_class")
							}
							if protRE != nil {
								for _, proto := range cat.Protocols {
									if protRE.MatchString(proto.Name) {
										fmt.Printf("    %s: %s\t%s=%s\t%s=%s\t%s=%s\n", colorAddr("%#09x", cat.Class.ClassPtr), filepath.Base(img.Name), colorField("protocol"), proto.Name, colorField("category"), swift.DemangleBlob(cat.Name), colorField(classType), swift.DemangleBlob(cat.Class.Name))
										break
									}
									// check for subprotocols
									for _, sub := range proto.Prots {
										if found, name, depth := recurseProtocols(protRE, sub, 1); found {
											if depth > 1 {
												fmt.Printf("    %s: %s\t%s=%s\t%s=%s %s=%d\t%s=%s\t%s=%s\n", colorAddr("%#09x", cat.Class.ClassPtr), filepath.Base(img.Name), colorField("protocol"), proto.Name, colorField("sub-protocol"), name, colorField("depth"), depth, colorField("category"), swift.DemangleBlob(cat.Name), colorField(classType), swift.DemangleBlob(cat.Class.Name))
											} else {
												fmt.Printf("    %s: %s\t%s=%s\t%s=%s\t%s=%s\t%s=%s\n", colorAddr("%#09x", cat.Class.ClassPtr), filepath.Base(img.Name), colorField("protocol"), proto.Name, colorField("sub-protocol"), name, colorField("category"), swift.DemangleBlob(cat.Name), colorField(classType), swift.DemangleBlob(cat.Class.Name))
											}
											break
										}
									}
								}
								for _, proto := range cat.Class.Protocols {
									if protRE.MatchString(proto.Name) {
										fmt.Printf("    %s: %s\t%s=%s\t%s=%s\t%s=%s\n", colorAddr("%#09x", cat.Class.ClassPtr), filepath.Base(img.Name), colorField("protocol"), proto.Name, colorField("category"), swift.DemangleBlob(cat.Name), colorField(classType), swift.DemangleBlob(cat.Class.Name))
										break
									}
									// check for subprotocols
									for _, sub := range proto.Prots {
										if found, name, depth := recurseProtocols(protRE, sub, 1); found {
											if depth > 1 {
												fmt.Printf("    %s: %s\t%s=%s\t%s=%s %s=%d\t%s=%s\t%s=%s\n", colorAddr("%#09x", cat.Class.ClassPtr), filepath.Base(img.Name), colorField("protocol"), proto.Name, colorField("sub-protocol"), name, colorField("depth"), depth, colorField("category"), swift.DemangleBlob(cat.Name), colorField(classType), swift.DemangleBlob(cat.Class.Name))
											} else {
												fmt.Printf("    %s: %s\t%s=%s\t%s=%s\t%s=%s\t%s=%s\n", colorAddr("%#09x", cat.Class.ClassPtr), filepath.Base(img.Name), colorField("protocol"), proto.Name, colorField("sub-protocol"), name, colorField("category"), swift.DemangleBlob(cat.Name), colorField(classType), swift.DemangleBlob(cat.Class.Name))
											}
											break
										}
									}
								}
							}
							if selRE != nil {
								for _, sel := range cat.Class.ClassMethods {
									if selRE.MatchString(sel.Name) {
										fmt.Printf("%s: %s\t%s=%s %s=%s %s=%s\n", colorAddr("%#09x", sel.ImpVMAddr), filepath.Base(img.Name), colorField("cat"), cat.Name, colorField(classType), cat.Class.Name, colorField("sel"), sel.Name)
										break
									}
								}
								for _, sel := range cat.Class.InstanceMethods {
									if selRE.MatchString(sel.Name) {
										fmt.Printf("%s: %s\t%s=%s %s=%s %s=%s\n", colorAddr("%#09x", sel.ImpVMAddr), filepath.Base(img.Name), colorField("cat"), cat.Name, colorField(classType), cat.Class.Name, colorField("sel"), sel.Name)
										break
									}
								}
							}
							if ivarRE != nil {
								for _, ivar := range cat.Class.Ivars {
									if ivarRE.MatchString(ivar.Name) {
										fmt.Printf("%s\t%s=%s %s=%s %s=%s\n", colorImage(img.Name), colorField("cat"), cat.Name, colorField(classType), cat.Class.Name, colorField("ivar"), ivar.Name)
										break
									}
								}
							}
						}
					} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
						log.Error(err.Error())
					}
				}
				if selRE != nil {
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
		}

		return nil
	},
}
