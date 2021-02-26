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
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/ota"
	"github.com/dustin/go-humanize"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(otaCmd)

	otaCmd.Flags().BoolP("info", "i", false, "Display OTA Info")
	otaCmd.MarkZshCompPositionalArgumentFile(1, "*.zip")
}

// otaCmd represents the ota command
var otaCmd = &cobra.Command{
	Use:   "ota <OTA.zip>",
	Short: "Extract file(s) from OTA",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		if _, err := os.Stat(args[0]); os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", args[0])
		}

		showInfo, _ := cmd.Flags().GetBool("info")

		if showInfo {
			pIPSW, err := info.Parse(args[0])
			if err != nil {
				return errors.Wrap(err, "failed to extract and parse IPSW info")
			}
			fmt.Println("\n[OTA Info]")
			fmt.Println("==========")
			fmt.Println(pIPSW)

			return nil
		}

		if len(args) > 1 {
			log.Infof("Extracting %s...", args[1])
			return ota.Extract(args[0], args[1])
		}

		log.Info("Listing files...")
		files, err := ota.List(args[0])
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.DiscardEmptyColumns)
		for _, f := range files {
			if !f.IsDir() {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", f.Mode(), f.ModTime().Format(time.RFC3339), humanize.Bytes(uint64(f.Size())), f.Name())
			}
		}
		w.Flush()

		return nil
	},
}
