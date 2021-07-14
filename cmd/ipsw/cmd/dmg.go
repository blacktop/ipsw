// +build darwin,cgo

/*
Copyright © 2021 blacktop

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
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/dmg"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(dmgCmd)
}

// dmgCmd represents the dmg command
var dmgCmd = &cobra.Command{
	Use:    "dmg",
	Short:  "🚧 Parse DMG file",
	Args:   cobra.MinimumNArgs(1),
	Hidden: true,
	Run: func(cmd *cobra.Command, args []string) {
		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		dmgPath := filepath.Clean(args[0])

		d, err := dmg.Open(dmgPath)
		if err != nil {
			panic(err)
		}
		defer d.Close()

		for _, block := range d.Blocks {
			if strings.Contains(block.Name, "Apple_APFS") {
				fo, err := os.Create("Apple_APFS.bin")
				if err != nil {
					panic(err)
				}
				defer func() {
					if err := fo.Close(); err != nil {
						panic(err)
					}
				}()
				w := bufio.NewWriter(fo)

				if err := block.DecompressChunks(w); err != nil {
					panic(err)
				}
			}
		}
	},
}
