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
package dyld

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/blacktop/ipsw/pkg/tbd"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DyldCmd.AddCommand(TbdCmd)
	TbdCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

// TbdCmd represents the tbd command
var TbdCmd = &cobra.Command{
	Use:   "tbd <dyld_shared_cache> <image>",
	Short: "Generate a .tbd file for a dylib",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
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

		image, err := f.Image(args[1])
		if err != nil {
			return fmt.Errorf("image not in %s: %v", dscPath, err)
		}
		t, err := tbd.NewTBD(f, image)
		if err != nil {
			return fmt.Errorf("failed to create tbd file for %s: %v", args[1], err)
		}

		outTBD, err := t.Generate()
		if err != nil {
			return fmt.Errorf("failed to create tbd file for %s: %v", args[1], err)
		}

		tbdFile := filepath.Base(t.Path)

		log.Info("Created " + tbdFile + ".tbd")
		err = os.WriteFile(tbdFile+".tbd", []byte(outTBD), 0660)
		if err != nil {
			return fmt.Errorf("failed to write tbd file %s: %v", tbdFile+".tbd", err)
		}

		return nil
	},
}
