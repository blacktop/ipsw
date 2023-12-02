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
	ObjcCmd.AddCommand(objcClassCmd)
	objcClassCmd.Flags().StringP("image", "i", "", "dylib image to search")
}

// objcClassCmd represents the class command
var objcClassCmd = &cobra.Command{
	Use:     "class <DSC>",
	Aliases: []string{"c"},
	Short:   "Get ObjC optimization class info",
	Args:    cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getDSCs(toComplete), cobra.ShellCompDirectiveDefault
	},
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

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
			ptrs, err := f.GetClassAddresses(args[1])
			if err != nil {
				return fmt.Errorf("failed to get class addresses: %v", err)
			}
			for _, ptr := range ptrs {
				fmt.Printf("%s: %s=%s\n", colorAddr("%#09x", ptr), colorClassField("class"), args[1])
			}
		} else {
			if len(imageName) > 0 {
				image, err := f.Image(imageName)
				if err != nil {
					return fmt.Errorf("failed to find image %s: %v", imageName, err)
				}
				m, err := image.GetMacho()
				if err != nil {
					return fmt.Errorf("failed to get macho for image %s: %v", imageName, err)
				}
				classes, err := m.GetObjCClassReferences()
				if err != nil {
					return fmt.Errorf("failed to get objc class references for image %s: %v", imageName, err)
				}
				for _, class := range classes {
					fmt.Printf("%s: %s\n", colorAddr("%#09x", class.ClassPtr), class.Name)
				}
			} else {
				if _, err := f.GetAllObjCClasses(true); err != nil {
					return fmt.Errorf("failed to get all objc classes: %s", err)
				}
			}
		}

		return nil
	},
}
