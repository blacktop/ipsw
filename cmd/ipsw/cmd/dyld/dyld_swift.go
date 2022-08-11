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
package dyld

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DyldCmd.AddCommand(SwiftCmd)
	SwiftCmd.Flags().BoolP("types", "t", false, "Print the types")
	// SwiftCmd.Flags().BoolP("sel", "s", false, "Print the selectors")
	// SwiftCmd.Flags().BoolP("proto", "p", false, "Print the protocols")
	// SwiftCmd.Flags().BoolP("imp-cache", "i", false, "Print the imp-caches")
	viper.BindPFlag("dyld.swift.types", SwiftCmd.Flags().Lookup("types"))

	SwiftCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

// SwiftCmd represents the swift command
var SwiftCmd = &cobra.Command{
	Use:           "swift",
	Short:         "Dump Swift Optimization Info",
	SilenceUsage:  true,
	SilenceErrors: true,
	Hidden:        true,
	Args:          cobra.MinimumNArgs(1),
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
				return errors.Wrapf(err, "failed to read symlink %s", dscPath)
			}
			// TODO: this seems like it would break
			linkParent := filepath.Dir(dscPath)
			linkRoot := filepath.Dir(linkParent)

			dscPath = filepath.Join(linkRoot, symlinkPath)
		}

		f, err := dyld.Open(dscPath)
		if err != nil {
			return fmt.Errorf("failed to open dyld shared cache %s: %w", dscPath, err)
		}
		defer f.Close()

		if viper.GetBool("dyld.swift.types") {
			if _, err := f.GetAllSwiftTypes(true); err != nil {
				return fmt.Errorf("failed to get swift types: %w", err)
			}
		}

		return nil
	},
}
