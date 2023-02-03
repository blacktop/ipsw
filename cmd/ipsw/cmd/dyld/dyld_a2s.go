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
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DyldCmd.AddCommand(AddrToSymCmd)
	AddrToSymCmd.Flags().Uint64P("slide", "s", 0, "dyld_shared_cache slide to apply")
	AddrToSymCmd.Flags().BoolP("image", "i", false, "Only lookup address's dyld_shared_cache mapping")
	AddrToSymCmd.Flags().BoolP("mapping", "m", false, "Only lookup address's image segment/section")
	AddrToSymCmd.Flags().String("cache", "", "Path to .a2s addr to sym cache file (speeds up analysis)")

	viper.BindPFlag("dyld.a2s.slide", AddrToSymCmd.Flags().Lookup("slide"))
	viper.BindPFlag("dyld.a2s.image", AddrToSymCmd.Flags().Lookup("image"))
	viper.BindPFlag("dyld.a2s.mapping", AddrToSymCmd.Flags().Lookup("mapping"))
	viper.BindPFlag("dyld.a2s.cache", AddrToSymCmd.Flags().Lookup("cache"))

	AddrToSymCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

// AddrToSymCmd represents the a2s command
var AddrToSymCmd = &cobra.Command{
	Use:           "a2s <dyld_shared_cache> <vaddr>",
	Short:         "Lookup symbol at unslid address",
	SilenceUsage:  false,
	SilenceErrors: true,
	Args:          cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		slide := viper.GetUint64("dyld.a2s.slide")
		showImage := viper.GetBool("dyld.a2s.image")
		showMapping := viper.GetBool("dyld.a2s.mapping")
		cacheFile := viper.GetString("dyld.a2s.cache")

		secondAttempt := false

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
				return fmt.Errorf("failed to read symlink %s", dscPath)
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

		if len(cacheFile) == 0 {
			cacheFile = dscPath + ".a2s"
		}
		if err := f.OpenOrCreateA2SCache(cacheFile); err != nil {
			return err
		}

	retry:
		if showMapping {
			uuid, mapping, err := f.GetMappingForVMAddress(unslidAddr)
			if err != nil {
				return err
			}

			var ext string
			ext, _ = f.GetSubCacheExtensionFromUUID(uuid)
			var stubs string
			if f.Headers[uuid].ImagesCount == 0 && f.Headers[uuid].ImagesCountOld == 0 {
				stubs = "STUB Island "
			}
			fmt.Printf("\nMAPPING\n")
			fmt.Printf("=======\n")
			fmt.Printf("  > %s(dsc%s) UUID: %s\n\n", stubs, ext, uuid.String())
			fmt.Println(mapping.String())
		}

		if image, err := f.GetImageContainingVMAddr(unslidAddr); err == nil {
			m, err := image.GetMacho()
			if err != nil {
				return err
			}
			defer m.Close()

			if showImage {
				fmt.Println("IMAGE")
				fmt.Println("-----")
				fmt.Printf(" > %s\n\n", image.Name)
			}

			if s := m.FindSegmentForVMAddr(unslidAddr); s != nil {
				if s.Nsect > 0 {
					if c := m.FindSectionForVMAddr(unslidAddr); c != nil {
						if showImage {
							fmt.Println(s)
							fmt.Println(c)
						} else {
							log.WithFields(log.Fields{
								"dylib":   image.Name,
								"section": fmt.Sprintf("%s.%s", s.Name, c.Name),
							}).Info("Address location")
						}
					}
				} else {
					log.WithFields(log.Fields{
						"dylib":   image.Name,
						"segment": s.Name,
					}).Info("Address location")
				}
			}

			// Load all symbols
			if err := image.Analyze(); err != nil {
				return err
			}

			if fn, err := m.GetFunctionForVMAddr(unslidAddr); err == nil {
				delta := ""
				if unslidAddr-fn.StartAddr != 0 {
					delta = fmt.Sprintf(" + %d", unslidAddr-fn.StartAddr)
				}
				if symName, ok := f.AddressToSymbol[fn.StartAddr]; ok {
					if secondAttempt {
						symName = "_ptr." + symName
					}
					fmt.Printf("\n%#x: %s%s\n", addr, symName, delta)
				} else {
					if secondAttempt {
						fmt.Printf("\n%#x: _ptr.func_%x%s\n", addr, fn.StartAddr, delta)
						return nil
					}
					fmt.Printf("\n%#x: func_%x%s\n", addr, fn.StartAddr, delta)
				}
				return nil
			}

			if cstr, ok := m.IsCString(unslidAddr); ok {
				if secondAttempt {
					fmt.Printf("\n%#x: _ptr.%#v\n", addr, cstr)
				} else {
					fmt.Printf("\n%#x: %#v\n", addr, cstr)
				}
				return nil
			}

		} else {
			log.Error(err.Error())
		}

		if symName, ok := f.AddressToSymbol[unslidAddr]; ok {
			if secondAttempt {
				symName = "_ptr." + symName
			}
			fmt.Printf("\n%#x: %s\n", addr, symName)
			return nil
		}

		if secondAttempt {
			log.Error("no symbol found")
			return nil
		}

		ptr, err := f.ReadPointerAtAddress(unslidAddr)
		if err != nil {
			return err
		}

		utils.Indent(log.Error, 2)(fmt.Sprintf("no symbol found (trying again with %#x as a pointer to %#x)", unslidAddr, f.SlideInfo.SlidePointer(ptr)))

		unslidAddr = f.SlideInfo.SlidePointer(ptr)

		secondAttempt = true

		goto retry
	},
}
