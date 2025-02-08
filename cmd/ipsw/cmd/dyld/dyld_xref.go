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
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/disass"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DyldCmd.AddCommand(XrefCmd)
	XrefCmd.Flags().StringP("image", "i", "", "Dylib image to search")
	XrefCmd.Flags().BoolP("imports", "", false, "Search all other dylibs that import the dylib containing the xref src")
	XrefCmd.Flags().BoolP("all", "a", false, "Search all images")
	XrefCmd.Flags().Uint64P("slide", "s", 0, "dyld_shared_cache slide to apply (not supported yet)")
	XrefCmd.Flags().String("cache", "", "Path to .a2s addr to sym cache file (speeds up analysis)")

	viper.BindPFlag("dyld.xref.image", XrefCmd.Flags().Lookup("image"))
	viper.BindPFlag("dyld.xref.imports", XrefCmd.Flags().Lookup("imports"))
	viper.BindPFlag("dyld.xref.all", XrefCmd.Flags().Lookup("all"))
	viper.BindPFlag("dyld.xref.slide", XrefCmd.Flags().Lookup("slide"))
	viper.BindPFlag("dyld.xref.cache", XrefCmd.Flags().Lookup("cache"))
}

// XrefCmd represents the xref command
var XrefCmd = &cobra.Command{
	Use:     "xref <DSC> <ADDR>",
	Aliases: []string{"x"},
	Short:   "🚧 [WIP] Find all cross references to an address",
	Args:    cobra.ExactArgs(2),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) != 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return getDSCs(toComplete), cobra.ShellCompDirectiveDefault
	},
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		imageName := viper.GetString("dyld.xref.image")
		// TODO: add slide support (add to output addrs)
		slide := viper.GetUint64("dyld.xref.slide")
		searchImports := viper.GetBool("dyld.xref.imports")
		allImages := viper.GetBool("dyld.xref.all")
		cacheFile := viper.GetString("dyld.xref.cache")

		addr, err := utils.ConvertStrToInt(args[1])
		if err != nil {
			return err
		}

		var unslidAddr uint64 = addr
		if slide > 0 {
			unslidAddr = addr - slide
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
			return err
		}
		defer f.Close()

		if !f.IsArm64() {
			log.Errorf("can only disassemble arm64 caches (disassembly required to find Xrefs)")
			return nil
		}

		var srcImage *dyld.CacheImage
		var images []*dyld.CacheImage
		if len(imageName) > 0 {
			srcImage, err = f.Image(imageName)
			if err != nil {
				return fmt.Errorf("image not in %s: %v", dscPath, err)
			}
			images = append(images, srcImage)
		} else if allImages {
			images = f.Images
		} else {
			srcImage, err = f.GetImageContainingVMAddr(unslidAddr)
			if err != nil {
				return err
			}
			images = append(images, srcImage)
		}

		if searchImports {
			log.Info("Searching for importing dylibs")
			for _, i := range f.Images {
				m, err := i.GetPartialMacho()
				if err != nil {
					return err
				}
				if utils.StrSliceHas(m.ImportedLibraries(), srcImage.Name) {
					images = append(images, i)
				}
				m.Close()
			}
		}

		if len(cacheFile) == 0 {
			cacheFile = dscPath + ".a2s"
		}
		if err := f.OpenOrCreateA2SCache(cacheFile); err != nil {
			return err
		}

		log.Info("Searching for xrefs (use -V for more progess output)")

		for _, img := range images {
			xrefs := make(map[uint64]string)

			if err := img.Analyze(); err != nil {
				return fmt.Errorf("failed to analyze image: %s; %v", img.Name, err)
			}

			m, err := img.GetMacho()
			if err != nil {
				return err
			}
			defer m.Close()

			if m.HasObjC() {
				log.Debug("Parsing ObjC runtime structures...")
				if err := f.ParseObjcForImage(img.Name); err != nil {
					return fmt.Errorf("failed to parse objc data for image %s: %v", img.Name, err)
				}
			}

			for _, fn := range m.GetFunctions() {
				uuid, soff, err := f.GetOffset(fn.StartAddr)
				if err != nil {
					return err
				}

				data, err := f.ReadBytesForUUID(uuid, int64(soff), uint64(fn.EndAddr-fn.StartAddr))
				if err != nil {
					return err
				}

				engine := dyld.NewDyldDisass(f, &disass.Config{
					Data:         data,
					StartAddress: fn.StartAddr,
					Quite:        true,
				})

				if err := engine.Triage(); err != nil {
					return fmt.Errorf("first pass triage failed: %v", err)
				}

				if ok, loc := engine.Contains(unslidAddr); ok {
					if sym, ok := f.AddressToSymbol[fn.StartAddr]; ok {
						xrefs[loc] = fmt.Sprintf("%s + %d", sym, loc-fn.StartAddr)
					} else {
						xrefs[loc] = fmt.Sprintf("func_%x + %d", fn.StartAddr, loc-fn.StartAddr)
					}
					// } else if triage.IsData(unslidAddr) {
					// 	xrefs[fn.StartAddr] = fmt.Sprintf("data_%x", fn.StartAddr)
					// } else {
					// 	if detail, ok := triage.Details[unslidAddr]; ok {
					// 		xrefs[fn.StartAddr] = detail.String()
					// 	}
					// }
				}
			}

			if len(xrefs) == 0 {
				log.WithFields(log.Fields{
					"dylib": img.Name,
				}).Debug("No XREFS found")
			} else {
				if symName, ok := f.AddressToSymbol[unslidAddr]; ok {
					log.WithFields(log.Fields{
						"sym":   symName,
						"dylib": img.Name,
						"xrefs": len(xrefs),
					}).Info("XREFS")
				} else {
					log.WithFields(log.Fields{
						"dylib": img.Name,
						"xrefs": len(xrefs),
					}).Info("XREFS")
				}
				if len(xrefs) > 0 {
					for addr, sym := range xrefs {
						fmt.Printf("%s: %s\n", colorAddr("%#x", addr), sym)
					}
				}
			}

			img.Free() // free up memory
		}

		return nil
	},
}
