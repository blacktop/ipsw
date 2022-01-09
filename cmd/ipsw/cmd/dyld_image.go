/*
Copyright © 2022 blacktop

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
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	dyldCmd.AddCommand(dyldImageCmd)

	dyldImageCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

// imageCmd represents the image command
var dyldImageCmd = &cobra.Command{
	Use:           "image <dyld_shared_cache> <IMAGE>",
	Short:         "Dump image array info",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
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

		if err := f.ParseImageArrays(); err != nil {
			return fmt.Errorf("failed parsing image arrays: %v", err)
		}

		if len(args) > 1 {
			imgName := args[1]
			if image, err := f.Image(imgName); err == nil {
				idx, err := f.GetDylibIndex(image.Name)
				if err != nil {
					return err
				}
				ci := f.ImageArray[uint32(idx+1)]
				fmt.Println(ci.String(f, Verbose))
				return nil
			} else {
				if id, err := f.GetDlopenOtherImageIndex(imgName); err == nil {
					ci := f.ImageArray[uint32(id)]
					fmt.Println(ci.String(f, Verbose))
					return nil
				} else {
					for _, clos := range f.Closures {
						for _, img := range clos.Images {
							if img.Name == imgName {
								fmt.Println(img.String(f, Verbose))
								return nil
							}
						}
					}
				}
				return fmt.Errorf("image %s not found (maybe try the FULL path)", imgName)
			}
		} else {
			for _, img := range f.ImageArray {
				fmt.Printf("%s\n", img.Name)
			}
		}

		return nil
	},
}
