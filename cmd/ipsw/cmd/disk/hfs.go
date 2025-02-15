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
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-apfs/pkg/disk/hfsplus"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DiskCmd.AddCommand(diskHfsCmd)

	diskHfsCmd.Flags().StringP("pattern", "p", "", "Extract files that match regex")
	diskHfsCmd.Flags().BoolP("flat", "f", false, "Do NOT preserve directory structure when extracting with --pattern")
	diskHfsCmd.Flags().StringP("output", "o", "", "Output folder")
	diskHfsCmd.MarkFlagDirname("output")
	viper.BindPFlag("disk.hfs.pattern", diskHfsCmd.Flags().Lookup("pattern"))
	viper.BindPFlag("disk.hfs.flat", diskHfsCmd.Flags().Lookup("flat"))
	viper.BindPFlag("disk.hfs.output", diskHfsCmd.Flags().Lookup("output"))
}

// diskHfsCmd represents the hfs command
var diskHfsCmd = &cobra.Command{
	Use:           "hfs",
	Short:         "🚧 List/Extract HFS+ files",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) (err error) {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		pattern := viper.GetString("disk.hfs.pattern")
		flat := viper.GetBool("disk.hfs.flat")
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

		if isHFS, err := magic.IsHFSPlus(infile); err != nil {
			return fmt.Errorf("failed to read HFS+ magic: %w", err)
		} else if !isHFS {
			return fmt.Errorf("file is not a HFS+ file")
		}

		hfs, err := hfsplus.Open(infile)
		if err != nil {
			return fmt.Errorf("failed to open HFS+: %w", err)
		}
		defer hfs.Close()

		files, err := hfs.Files()
		if err != nil {
			return fmt.Errorf("failed to get files: %w", err)
		}

		for _, hf := range files {
			if len(pattern) > 0 {
				re, err := regexp.Compile(pattern)
				if err != nil {
					return fmt.Errorf("failed to compile regex: %w", err)
				}
				if re.MatchString(hf.Path()) {
					fname := filepath.Join(output, hf.Path())
					if flat {
						fname = filepath.Join(output, filepath.Base(hf.Path()))
					}
					if err := os.MkdirAll(filepath.Dir(fname), 0o755); err != nil {
						return fmt.Errorf("failed to create directory: %w", err)
					}
					ff, err := os.Create(fname)
					if err != nil {
						return fmt.Errorf("failed to create file: %w", err)
					}
					defer ff.Close()
					if _, err := io.Copy(ff, hf.Reader()); err != nil {
						return fmt.Errorf("failed to copy file: %w", err)
					}
					log.Infof("Extracted %s", strings.TrimPrefix(fname, cwd+"/"))
				}
			} else {
				fmt.Println(hf.Path())
			}
		}

		return nil
	},
}
