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
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

// objcSelCmd represents the sel command
var objcSelCmd = &cobra.Command{
	Use:   "sel",
	Short: "Get ObjC selector info",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		imageName, _ := cmd.Flags().GetString("image")

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

		if len(args) > 1 {
			ptr, err := f.GetSelectorAddress(args[1])
			if err != nil {
				return err
			}
			fmt.Printf("0x%x: %s\n", ptr, args[1])
		} else {
			if len(imageName) > 0 {
				err = f.SelectorsForImage(imageName)
				if err != nil {
					return err
				}

				// sort by address
				addrs := make([]uint64, 0, len(f.AddressToSymbol))
				for a := range f.AddressToSymbol {
					addrs = append(addrs, a)
				}
				sort.Slice(addrs, func(i, j int) bool { return addrs[i] < addrs[j] })

				for _, addr := range addrs {
					fmt.Printf("%#x: %s\n", addr, f.AddressToSymbol[addr])
				}

			} else {
				_, err := f.GetAllSelectors(true)
				if err != nil {
					return err
				}
			}
		}

		return nil
	},
}

func init() {
	dyldObjcCmd.AddCommand(objcSelCmd)

	objcSelCmd.Flags().StringP("image", "i", "", "dylib image to search")
	objcSelCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}
