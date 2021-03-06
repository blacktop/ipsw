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
	"runtime"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/spf13/cobra"
)

func init() {
	dyldCmd.AddCommand(extractDyldCmd)

	extractDyldCmd.MarkZshCompPositionalArgumentFile(1, "*.ipsw")
}

// extractDyldCmd represents the extractDyld command
var extractDyldCmd = &cobra.Command{
	Use:   "extract <IPSW> <DEST>",
	Short: "Extract dyld_shared_cache from DMG in IPSW",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if Verbose {
			log.SetLevel(log.DebugLevel)
		}
		var destPath string
		ipswPath := filepath.Clean(args[0])
		if len(args) > 1 {
			destPath = filepath.Clean(args[1])
		}
		if _, err := os.Stat(ipswPath); os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", ipswPath)
		}

		if runtime.GOOS == "windows" {
			log.Fatal("dyld_shared_cache extraction does not work on Windows :(")
		}

		log.Info("Extracting dyld_shared_cache")
		return dyld.Extract(ipswPath, destPath)
	},
}
