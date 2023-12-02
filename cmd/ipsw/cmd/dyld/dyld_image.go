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
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/fatih/color"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DyldCmd.AddCommand(ImageCmd)
}

// imageCmd represents the image command
var ImageCmd = &cobra.Command{
	Use:     "image <DSC> <DYLIB>",
	Aliases: []string{"img"},
	Short:   "Dump image array info",
	Args:    cobra.MaximumNArgs(2),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) == 1 {
			return getImages(args[0]), cobra.ShellCompDirectiveDefault
		}
		return getDSCs(toComplete), cobra.ShellCompDirectiveDefault
	},
	SilenceErrors: true,
	Example: `  # List all the apps
  ❯ ipsw dyld image DSC
  # Dump the closure info for a in-cache dylib
  ❯ ipsw dyld image DSC Foundation
  # Dump the closure info for an app
  ❯ ipsw dyld image DSC /usr/libexec/timed`,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

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

		// if err := f.ForEachLaunchLoaderSet(func(execPath string, pset *dyld.PrebuiltLoaderSet) {
		// 	fmt.Println(pset.String(f))
		// }); err != nil {
		// 	if !errors.Is(err, dyld.ErrPrebuiltLoaderSetNotSupported) {
		// 		log.Errorf("failed parsing launch loader sets: %v", err)
		// 	}
		// }

		if len(args) > 1 {
			if image, err := f.Image(args[1]); err == nil {
				if pbl, err := f.GetDylibPrebuiltLoader(image.Name); err == nil {
					fmt.Println(pbl.String(f))
				} else {
					if !errors.Is(err, dyld.ErrPrebuiltLoaderSetNotSupported) {
						return fmt.Errorf("failed parsing launch loader sets: %v", err)
					}
					// try to parse the dylib closures using the old iOS14.x method
					idx, err := f.GetDylibIndex(image.Name)
					if err != nil {
						return err
					}
					if err := f.ParseImageArrays(); err != nil {
						return fmt.Errorf("failed parsing image arrays: %v", err)
					}
					ci := f.ImageArray[uint32(idx+1)]
					fmt.Println(ci.String(f, viper.GetBool("verbose")))
				}
				return nil
			} else {
				if pset, err := f.GetLaunchLoaderSet(args[1]); err == nil {
					fmt.Println(pset.String(f))
				} else {
					if !errors.Is(err, dyld.ErrPrebuiltLoaderSetNotSupported) {
						return fmt.Errorf("failed parsing launch loader sets: %v", err)
					}
					// try to parse the app closures using the old iOS14.x method
					if id, err := f.GetDlopenOtherImageIndex(args[1]); err == nil {
						if err := f.ParseImageArrays(); err != nil {
							return fmt.Errorf("failed parsing image arrays: %v", err)
						}
						ci := f.ImageArray[uint32(id)]
						fmt.Println(ci.String(f, viper.GetBool("verbose")))
						return nil
					} else {
						for _, clos := range f.Closures {
							for _, img := range clos.Images {
								if img.Name == args[1] {
									fmt.Println(img.String(f, viper.GetBool("verbose")))
									return nil
								}
							}
						}
					}
					return fmt.Errorf("image %s not found (maybe try the FULL path)", args[1])
				}
			}
		} else {
			if err := f.ForEachLaunchLoaderSetPath(func(execPath string) {
				fmt.Println(execPath)
			}); err != nil {
				if !errors.Is(err, dyld.ErrPrebuiltLoaderSetNotSupported) {
					return fmt.Errorf("failed parsing launch loader sets: %v", err)
				}
				// try to parse the image array using the old iOS14.x method
				if err := f.ParseImageArrays(); err != nil {
					return fmt.Errorf("failed parsing image arrays: %v", err)
				}
				for _, img := range f.ImageArray {
					fmt.Printf("%s\n", img.Name)
				}
			}
		}

		return nil
	},
}
