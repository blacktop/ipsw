//go:build !windows

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
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/spf13/cobra"
)

func init() {
	dyldCmd.AddCommand(extractDyldCmd)
	extractDyldCmd.Flags().StringArrayP("dyld-arch", "a", []string{}, "dyld_shared_cache architecture to extract")
	extractDyldCmd.MarkZshCompPositionalArgumentFile(1, "*.ipsw")
}

// extractDyldCmd represents the extractDyld command
var extractDyldCmd = &cobra.Command{
	Use:           "extract <IPSW> <DEST>",
	Short:         "Extract dyld_shared_cache from DMG in IPSW",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		dyldArches, _ := cmd.Flags().GetStringArray("dyld-arch")

		if len(dyldArches) > 0 {
			for _, arch := range dyldArches {
				if !utils.StrSliceHas([]string{"arm64", "arm64e", "x86_64", "x86_64h"}, arch) {
					return fmt.Errorf("invalid architecture: %s (must be: arm64, arm64e, x86_64 or x86_64h)", arch)
				}
			}
		}

		ipswPath := filepath.Clean(args[0])

		var destPath string
		if len(args) > 1 {
			destPath = filepath.Clean(args[1])
		}

		if _, err := os.Stat(ipswPath); os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", ipswPath)
		}

		i, err := info.Parse(ipswPath)
		if err != nil {
			return fmt.Errorf("failed to parse ipsw info: %v", err)
		}

		destPath = filepath.Join(destPath, i.GetFolder())

		log.Info("Extracting dyld_shared_cache")
		return dyld.Extract(ipswPath, destPath, dyldArches)
	},
}
