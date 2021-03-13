/*
Copyright © 2021 blacktop

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
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-arm64"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	dyldCmd.AddCommand(xrefCmd)

	xrefCmd.Flags().StringP("image", "i", "", "dylib image to search")
	xrefCmd.Flags().Uint64P("slide", "s", 0, "dyld_shared_cache slide to apply")

	xrefCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

// xrefCmd represents the xref command
var xrefCmd = &cobra.Command{
	Use:   "xref [options] <dyld_shared_cache> <vaddr>",
	Short: "🚧 [WIP] Find all cross references to an address",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		xrefs := make(map[uint64]string)

		imageName, _ := cmd.Flags().GetString("image")

		// TODO: add slide support (add to output addrs)
		slide, _ := cmd.Flags().GetUint64("slide")

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

		f, err := dyld.Open(dscPath, &dyld.Config{ParsePatchInfo: true})
		if err != nil {
			return err
		}
		defer f.Close()

		var image *dyld.CacheImage
		if len(imageName) > 0 {
			image = f.Image(imageName)
			if image == nil {
				return fmt.Errorf("no image found matching %s", imageName)
			}
		} else {
			image, err = f.GetImageContainingVMAddr(unslidAddr)
			if err != nil {
				return err
			}
		}

		if err := f.AnalyzeImage(image); err != nil {
			return fmt.Errorf("failed to analyze image: %s; %v", image.Name, err)
		}

		m, err := image.GetMacho()
		if err != nil {
			return err
		}
		defer m.Close()

		if m.HasObjC() {
			log.Debug("Parsing ObjC runtime structures...")
			if err := f.CFStringsForImage(image.Name); err != nil {
				return errors.Wrapf(err, "failed to parse objc cfstrings")
			}
			if err := f.MethodsForImage(image.Name); err != nil {
				return errors.Wrapf(err, "failed to parse objc methods")
			}
			if err := f.SelectorsForImage(image.Name); err != nil {
				return errors.Wrapf(err, "failed to parse objc selectors")
			}
			if err := f.ClassesForImage(image.Name); err != nil {
				return errors.Wrapf(err, "failed to parse objc classes")
			}
		}

		if symName, ok := f.AddressToSymbol[unslidAddr]; ok {
			log.WithFields(log.Fields{
				"sym":   symName,
				"dylib": image.Name,
			}).Info("Address location")
		} else {
			log.WithFields(log.Fields{
				"dylib": image.Name,
			}).Info("Address location")
		}

		for _, fn := range m.GetFunctions() {
			soff, err := f.GetOffset(fn.StartAddr)
			if err != nil {
				return err
			}

			data, err := f.ReadBytes(int64(soff), uint64(fn.EndAddr-fn.StartAddr))
			if err != nil {
				return err
			}

			triage, err := f.FirstPassTriage(m, &fn, bytes.NewReader(data), arm64.Options{StartAddress: int64(fn.StartAddr)}, false)
			if err != nil {
				return err
			}

			if ok, loc := triage.Contains(unslidAddr); ok {
				if sym := f.FindSymbol(fn.StartAddr, false); len(sym) > 0 {
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

		if len(xrefs) > 0 {
			title := fmt.Sprintf("XREFS (%d)", len(xrefs))
			fmt.Printf("\n%s\n", title)
			fmt.Println(strings.Repeat("=", len(title)))
			for addr, sym := range xrefs {
				fmt.Printf("%#x: %s\n", addr, sym)
			}
		} else {
			log.Info("No XREFS found")
		}

		return nil
	},
}
