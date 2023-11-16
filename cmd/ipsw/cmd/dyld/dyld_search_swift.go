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
	"github.com/blacktop/go-macho/types/swift"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	dyldSearchCmd.AddCommand(dyldSearchSwiftCmd)

	dyldSearchSwiftCmd.Flags().StringSliceP("image", "i", []string{}, "Images to search (default: all)")
	dyldSearchSwiftCmd.Flags().StringP("class", "c", "", "Search for specific Swift class regex")
	dyldSearchSwiftCmd.Flags().StringP("protocol", "p", "", "Search for specific Swift protocol regex")
	viper.BindPFlag("dyld.search.swift.image", dyldSearchSwiftCmd.Flags().Lookup("image"))
	viper.BindPFlag("dyld.search.swift.class", dyldSearchSwiftCmd.Flags().Lookup("class"))
	viper.BindPFlag("dyld.search.swift.protocol", dyldSearchSwiftCmd.Flags().Lookup("protocol"))
	// dyldSearchSwiftCmd.MarkFlagsMutuallyExclusive("class", "")
}

// dyldSearchSwiftCmd represents the swift command
var dyldSearchSwiftCmd = &cobra.Command{
	Use:     "swift <DSC>",
	Aliases: []string{"s"},
	Short:   "Find Dylib files for given Swift search criteria",
	Args:    cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getDSCs(toComplete), cobra.ShellCompDirectiveDefault
	},
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) (err error) {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		searchImages := viper.GetStringSlice("dyld.search.swift.image")
		classReStr := viper.GetString("dyld.search.swift.class")
		protocolReStr := viper.GetString("dyld.search.swift.protocol")
		// verify flags
		if classReStr == "" && protocolReStr == "" {
			return fmt.Errorf("must specify a search criteria via one of the flags")
		}
		// compile regexes
		var classRE *regexp.Regexp
		if classReStr != "" {
			classRE, err = regexp.Compile(classReStr)
			if err != nil {
				return fmt.Errorf("invalid regex '%s': %w", classReStr, err)
			}
		}
		var protocolRE *regexp.Regexp
		if protocolReStr != "" {
			protocolRE, err = regexp.Compile(protocolReStr)
			if err != nil {
				return fmt.Errorf("invalid regex '%s': %w", protocolReStr, err)
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

		for _, image := range images {
			m, err := image.GetMacho()
			if err != nil {
				return err
			}
			if m.HasSwift() {
				if err := m.PreCache(); err != nil { // cache fields and types
					log.Errorf("failed to precache swift fields/types for %s: %v", filepath.Base(image.Name), err)
				}
				if classRE != nil || protocolRE != nil {
					if typs, err := m.GetSwiftTypes(); err == nil {
						for _, typ := range typs {
							switch typ.Kind {
							case swift.CDKindClass:
								if classRE != nil && classRE.MatchString(typ.Name) {
									fmt.Printf("%s: %s\t%s=%s\n", colorAddr("%#09x", typ.Address), colorImage(filepath.Base(image.Name)), colorField("class"), typ.Name)
								}
							case swift.CDKindProtocol:
								if protocolRE != nil && protocolRE.MatchString(typ.Name) {
									fmt.Printf("%s: %s\t%s=%s\n", colorAddr("%#09x", typ.Address), colorImage(filepath.Base(image.Name)), colorField("protocol"), typ.Name)
								}
							}
						}
					} else if !errors.Is(err, macho.ErrSwiftSectionError) {
						log.Errorf("failed to parse swift types for %s: %v", filepath.Base(image.Name), err)
					}
				}
				if protocolRE != nil {
					if prots, err := m.GetSwiftProtocols(); err == nil {
						for _, typ := range prots {
							if protocolRE.MatchString(typ.Name) {
								fmt.Printf("%s: %s\t%s=%s\n", colorAddr("%#09x", typ.Address), colorImage(filepath.Base(image.Name)), colorField("protocol"), typ.Name)
							}
						}
					} else if !errors.Is(err, macho.ErrSwiftSectionError) {
						log.Errorf("failed to parse swift protocols for %s: %v", filepath.Base(image.Name), err)
					}
					if confs, err := m.GetSwiftProtocolConformances(); err == nil {
						for _, conf := range confs {
							if protocolRE.MatchString(conf.Protocol) {
								typName := conf.TypeRef.Name
								if conf.TypeRef.Parent != nil && conf.TypeRef.Parent.Name != "" {
									typName = conf.TypeRef.Parent.Name + "." + typName
									if conf.TypeRef.Parent.Parent != nil && conf.TypeRef.Parent.Parent.Name != "" {
										typName = conf.TypeRef.Parent.Parent.Name + "." + typName
									}
								}
								fmt.Printf("%s: %s\t%s=%s\t%s=%s\n", colorAddr("%#09x", conf.Address), colorImage(filepath.Base(image.Name)), colorField("conformance"), conf.Protocol, colorField("type"), typName)
							}
						}
					} else if !errors.Is(err, macho.ErrSwiftSectionError) {
						log.Errorf("failed to parse swift protocols for %s: %v", filepath.Base(image.Name), err)
					}
				}
			}
		}

		return nil
	},
}
