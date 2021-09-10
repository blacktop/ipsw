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
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/apfs"
	"github.com/blacktop/ipsw/pkg/disk/dmg"
	"github.com/spf13/cobra"
)

func init() {
	apfsCmd.AddCommand(apfsLsCmd)
}

// apfsLsCmd represents the ls command
var apfsLsCmd = &cobra.Command{
	Use:    "ls <DMG> <PATH>",
	Short:  "🚧 List files in APFS container",
	Args:   cobra.MinimumNArgs(1),
	Hidden: true,
	Run: func(cmd *cobra.Command, args []string) {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		dmgPath := filepath.Clean(args[0])

		dev, err := dmg.Open(dmgPath)
		if err != nil {
			log.Fatal(err.Error())
		}
		defer dev.Close()

		a, err := apfs.NewAPFS(dev)
		if err != nil {
			log.Fatal(err.Error())
		}
		defer a.Close()

		if len(args) > 1 {
			if err := a.List(args[1]); err != nil {
				log.Fatal(err.Error())
			}
		} else {
			if err := a.List("/"); err != nil {
				log.Fatal(err.Error())
			}
		}
	},
}
