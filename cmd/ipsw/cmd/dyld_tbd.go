/*
Copyright © 2020 blacktop

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
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/tbd"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	dyldCmd.AddCommand(tbdCmd)

	tbdCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

// tbdCmd represents the tbd command
var tbdCmd = &cobra.Command{
	Use:    "tbd <dyld_shared_cache> <image>",
	Short:  "Generate a .tbd file for a dylib",
	Args:   cobra.MinimumNArgs(2),
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		fileInfo, err := os.Lstat(args[0])
		if err != nil {
			return fmt.Errorf("file %s does not exist", args[0])
		}

		dyldFile := args[0]

		// Check if file is a symlink
		if fileInfo.Mode()&os.ModeSymlink != 0 {
			dyldFile, err = os.Readlink(args[0])
			if err != nil {
				return errors.Wrapf(err, "failed to read symlink %s", args[0])
			}
			// TODO: this seems like it would break
			linkParent := filepath.Dir(args[0])
			linkRoot := filepath.Dir(linkParent)

			dyldFile = filepath.Join(linkRoot, dyldFile)
		}

		t, err := tbd.NewTBD(args[0], args[1])
		if err != nil {
			return errors.Wrapf(err, "failed to create tbd file for %s", args[1])
		}

		outTBD, err := t.Generate()
		if err != nil {
			return errors.Wrapf(err, "failed to create tbd file for %s", args[1])
		}

		tbdFile := filepath.Base(t.Path)

		err = ioutil.WriteFile(tbdFile+".tbd", []byte(outTBD), 0644)
		if err != nil {
			return errors.Wrapf(err, "failed to write tbd file %s", tbdFile+".tbd")
		}

		return nil
	},
}
