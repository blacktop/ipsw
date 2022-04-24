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
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	kernelcacheCmd.AddCommand(libsandboxCmd)

	libsandboxCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

// libsandboxCmd represents the libsandbox command
var libsandboxCmd = &cobra.Command{
	Use:           "libsandbox",
	Short:         "🚧 [WIP] Get libsandbox data",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	Hidden:        true,
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

		fi, err := kernelcache.GetFilterInfo(f)
		if err != nil {
			return err
		}

		fmt.Println("Filter Info")
		fmt.Println("===========")
		for idx, filter := range fi {
			fmt.Printf("%02d: %s\t(%s)\n", idx, filter.Name, filter.Category)
			if len(filter.Aliases) > 0 {
				for _, alias := range filter.Aliases {
					fmt.Printf("    %d) %s\n", alias.Value, alias.Name)
				}
			}
		}

		mi, err := kernelcache.GetModifierInfo(f)
		if err != nil {
			return err
		}
		fmt.Println()
		fmt.Println("Modifier Info")
		fmt.Println("=============")
		for idx, modifier := range mi {
			fmt.Printf("%02d: %s\n", idx, modifier.Name)
			if len(modifier.Aliases) > 0 {
				for _, alias := range modifier.Aliases {
					fmt.Printf("    %d) %s\n", alias.Value, alias.Name)
				}
			}
		}

		oi, err := kernelcache.GetOperationInfo(f)
		if err != nil {
			return err
		}

		fmt.Println()
		fmt.Println("Operation Names")
		fmt.Println("===============")
		for idx, o := range oi {
			fmt.Printf("%02d: %s\n", idx, o.Name)
		}

		return nil
	},
}
