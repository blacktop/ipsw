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

	"github.com/apex/log"
	"github.com/blacktop/go-arm64"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	dyldCmd.AddCommand(xrefCmd)

	xrefCmd.Flags().Uint64P("slide", "s", 0, "dyld_shared_cache slide to apply")

	xrefCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

// xrefCmd represents the xref command
var xrefCmd = &cobra.Command{
	Use:    "xref [options] <dyld_shared_cache> <vaddr>",
	Short:  "🚧 [WIP] Find all cross references to an address",
	Args:   cobra.MinimumNArgs(2),
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		xrefs := make(map[uint64]string)
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

		image, err := f.GetImageContainingVMAddr(unslidAddr)
		if err != nil {
			return err
		}

		log.WithFields(log.Fields{
			"dylib": image.Name,
		}).Info("Address location")

		if err := f.AnalyzeImage(image); err != nil {
			return fmt.Errorf("failed to analyze image: %s; %#v", image.Name, err)
		}

		m, err := image.GetPartialMacho()
		if err != nil {
			return err
		}
		defer m.Close()

		for _, fn := range m.GetFunctions() {
			soff, err := f.GetOffset(fn.StartAddr)
			if err != nil {
				return err
			}

			data, err := f.ReadBytes(int64(soff), uint64(fn.EndAddr-fn.StartAddr))
			if err != nil {
				return err
			}

			addrs := f.FirstPass(bytes.NewReader(data), arm64.Options{StartAddress: int64(fn.StartAddr)})

			if utils.Uint64SliceContains(addrs, unslidAddr) {
				sym := f.FindSymbol(fn.StartAddr, false)
				if len(sym) > 0 {
					xrefs[fn.StartAddr] = sym
				} else {
					xrefs[fn.StartAddr] = fmt.Sprintf("func_%x", fn.StartAddr)
				}
			}
		}

		fmt.Println("XREFS")
		fmt.Println("=====")
		for addr, sym := range xrefs {
			fmt.Printf("%#x: %s\n", addr, sym)
		}

		return nil
	},
}
