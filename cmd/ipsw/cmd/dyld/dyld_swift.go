/*
Copyright © 2018-2025 blacktop

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
	DyldCmd.AddCommand(SwiftCmd)
	SwiftCmd.Flags().BoolP("types", "t", false, "Print the type conformances")
	SwiftCmd.Flags().BoolP("metadata", "m", false, "Print the metadata conformances")
	SwiftCmd.Flags().BoolP("foreign", "f", false, "Print the foreign type conformances")
	SwiftCmd.Flags().BoolP("demangle", "d", false, "Demangle the Swift symbols")
	SwiftCmd.Flags().String("cache", "", "Path to .a2s addr to sym cache file (speeds up analysis)")

	viper.BindPFlag("dyld.swift.types", SwiftCmd.Flags().Lookup("types"))
	viper.BindPFlag("dyld.swift.metadata", SwiftCmd.Flags().Lookup("metadata"))
	viper.BindPFlag("dyld.swift.foreign", SwiftCmd.Flags().Lookup("foreign"))
	viper.BindPFlag("dyld.swift.demangle", SwiftCmd.Flags().Lookup("demangle"))
	viper.BindPFlag("dyld.swift.cache", SwiftCmd.Flags().Lookup("cache"))
}

// SwiftCmd represents the swift command
var SwiftCmd = &cobra.Command{
	Use:   "swift <DSC>",
	Short: "Dump Swift Optimizations Info",
	Args:  cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getDSCs(toComplete), cobra.ShellCompDirectiveDefault
	},
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		if !viper.GetBool("dyld.swift.types") && !viper.GetBool("dyld.swift.metadata") && !viper.GetBool("dyld.swift.foreign") {
			return fmt.Errorf("must specify at least one of the following flags: --types, --metadata, --foreign")
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

		cacheFile := viper.GetString("dyld.swift.cache")

		if len(cacheFile) == 0 {
			cacheFile = dscPath + ".a2s"
		}
		if err := f.OpenOrCreateA2SCache(cacheFile); err != nil {
			return err
		}

		if viper.GetBool("dyld.swift.types") {
			if err := f.GetAllSwiftTypes(true, viper.GetBool("dyld.swift.demangle")); err != nil {
				return fmt.Errorf("failed to get swift types: %w", err)
			}
		}
		if viper.GetBool("dyld.swift.metadata") {
			if err := f.GetAllSwiftMetadatas(true, viper.GetBool("dyld.swift.demangle")); err != nil {
				return fmt.Errorf("failed to get swift types: %w", err)
			}
		}
		if viper.GetBool("dyld.swift.foreign") {
			if err := f.GetAllSwiftForeignTypes(true, viper.GetBool("dyld.swift.demangle")); err != nil {
				return fmt.Errorf("failed to get swift types: %w", err)
			}
		}

		return nil
	},
}
