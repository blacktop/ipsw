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
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/bom"
	"github.com/dustin/go-humanize"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(lsbomCmd)
}

// lsbomCmd represents the lsbom command
var lsbomCmd = &cobra.Command{
	Use:           "lsbom",
	Short:         "List contents of a BOM file",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		bomPath := filepath.Clean(args[0])

		f, err := os.Open(bomPath)
		if err != nil {
			return err
		}
		defer f.Close()

		bm, err := bom.New(f)
		if err != nil {
			return err
		}

		files, err := bm.GetPaths()
		if err != nil {
			return err
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.DiscardEmptyColumns)
		for _, f := range files {
			if f.IsDir() {
				// fmt.Fprintf(w, "%s\t%s\t%s\n", f.Mode(), f.ModTime().Format(time.RFC3339), f.Name())
			} else {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", f.Mode(), f.ModTime().Format(time.RFC3339), humanize.Bytes(uint64(f.Size())), f.Name())
			}
		}
		w.Flush()

		return nil
	},
}
