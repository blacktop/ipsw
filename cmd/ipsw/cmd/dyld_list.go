/*
Copyright © 2019 blacktop

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
	dyldCmd.AddCommand(dyldListCmd)

	dyldListCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

// dyldListCmd represents the list command
var dyldListCmd = &cobra.Command{
	Use:   "list <dyld_shared_cache>",
	Short: "List all dylibs in dyld_shared_cache",
	Args:  cobra.MinimumNArgs(1),
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

		// TODO: check for
		// if ( dylibInfo->isAlias )
		//   	printf("[alias] %s\n", dylibInfo->path);

		f, err := dyld.Open(dyldFile)
		if err != nil {
			return err
		}
		defer f.Close()

		f.CacheHeader.Print()
		// f.LocalSymInfo.Print()
		fmt.Println()
		f.Mappings.Print()
		fmt.Println()
		fmt.Println("Images")
		fmt.Println("======")

		for idx, img := range f.Images {
			m, err := img.GetPartialMacho()
			if err != nil {
				return errors.Wrap(err, "failed to create MachO")
			}
			fmt.Printf("%4d:\t0x%0X\t%s\t(%s)\n", idx+1, img.Info.Address, img.Name, m.DylibID().CurrentVersion)
		}

		return nil
	},
}
