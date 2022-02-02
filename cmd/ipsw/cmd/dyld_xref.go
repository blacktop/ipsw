/*
Copyright © 2018-2022 blacktop

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
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/disass"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	dyldCmd.AddCommand(xrefCmd)

	xrefCmd.Flags().StringP("image", "i", "", "dylib image to search")
	xrefCmd.Flags().Uint64P("slide", "s", 0, "dyld_shared_cache slide to apply")
	xrefCmd.Flags().BoolP("imports", "", false, "Search all other dylibs that import the dylib containing the xref src")

	xrefCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

// xrefCmd represents the xref command
var xrefCmd = &cobra.Command{
	Use:   "xref <dyld_shared_cache> <vaddr>",
	Short: "🚧 [WIP] Find all cross references to an address",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		imageName, _ := cmd.Flags().GetString("image")

		// TODO: add slide support (add to output addrs)
		slide, _ := cmd.Flags().GetUint64("slide")
		searchImports, _ := cmd.Flags().GetBool("imports")

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

			msg := "XREFS"
			if len(xrefs) == 0 {
				msg = "No XREFS found"
			}
			if symName, ok := f.AddressToSymbol[unslidAddr]; ok {
				log.WithFields(log.Fields{
					"sym":   symName,
					"dylib": img.Name,
					"xrefs": len(xrefs),
				}).Info(msg)
			} else {
				log.WithFields(log.Fields{
					"dylib": img.Name,
					"xrefs": len(xrefs),
				}).Info(msg)
			}
			if len(xrefs) > 0 {
				for addr, sym := range xrefs {
					fmt.Printf("%#x: %s\n", addr, sym)
				}
			}
		}

		return nil
	},
}
