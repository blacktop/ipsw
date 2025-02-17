/*
Copyright © 2025 blacktop

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
package disk

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/go-apfs"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DiskCmd.AddCommand(apfsCmd)

	apfsCmd.Flags().StringP("path", "p", "", "Path to list inside APFS")
	// apfsCmd.Flags().StringP("search", "r", "", "Extract files that match regex")
	// apfsCmd.Flags().BoolP("flat", "f", false, "Do NOT preserve directory structure when extracting with --search")
	apfsCmd.Flags().StringP("output", "o", "", "Output folder")
	apfsCmd.MarkFlagDirname("output")
	viper.BindPFlag("disk.apfs.path", apfsCmd.Flags().Lookup("path"))
	// viper.BindPFlag("disk.apfs.search", apfsCmd.Flags().Lookup("search"))
	// viper.BindPFlag("disk.apfs.flat", apfsCmd.Flags().Lookup("flat"))
	viper.BindPFlag("disk.apfs.output", apfsCmd.Flags().Lookup("output"))
}

// apfsCmd represents the apfs command
var apfsCmd = &cobra.Command{
	Use:           "apfs",
	Short:         "🚧 List/Extract APFS files",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	Hidden:        true,
	RunE: func(cmd *cobra.Command, args []string) (err error) {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		// pattern := viper.GetString("disk.hfs.search")
		// flat := viper.GetBool("disk.hfs.flat")
		root := viper.GetString("disk.apfs.path")
		output := viper.GetString("disk.hfs.output")

		var cwd string
		if len(output) == 0 {
			cwd, err = os.Getwd()
			if err != nil {
				return fmt.Errorf("failed to get current working directory: %w", err)
			}
			output = cwd
		}

		infile := filepath.Clean(args[0])

		if isAPFS, err := magic.IsAPFS(infile); err != nil {
			return fmt.Errorf("failed to read APFS magic: %w", err)
		} else if !isAPFS {
			return fmt.Errorf("file is not an APFS file")
		}

		fs, err := apfs.Open(infile)
		if err != nil {
			return err
		}
		defer fs.Close()

		if err := fs.List(root); err != nil {
			return err
		}

		return nil
	},
}
