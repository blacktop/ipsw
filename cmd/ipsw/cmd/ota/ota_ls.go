/*
Copyright © 2018-2024 blacktop

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
package ota

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/ota"
	"github.com/dustin/go-humanize"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	OtaCmd.AddCommand(otaLsCmd)

	otaLsCmd.Flags().BoolP("bom", "b", false, "List the post.bom files")
	viper.BindPFlag("ota.ls.bom", otaLsCmd.Flags().Lookup("bom"))
}

// otaLsCmd represents the ls command
var otaLsCmd = &cobra.Command{
	Use:           "ls <OTA>",
	Aliases:       []string{"l"},
	Short:         "List OTA files",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		ota, err := ota.Open(filepath.Clean(args[0]))
		if err != nil {
			return fmt.Errorf("failed to open OTA file: %v", err)
		}
		defer ota.Close()

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.DiscardEmptyColumns)

		if viper.GetBool("ota.ls.bom") {
			fmt.Fprintf(w, "\n- [ PAYLOAD FILES    ] %s\n\n", strings.Repeat("-", 50))
			fmt.Fprintf(w, "      (OTA might not actually contain all these files if it is a partial update file)\n\n")
			for _, f := range ota.PostFiles() {
				if !f.IsDir() {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", colorMode(f.Mode()), colorModTime(f.ModTime().Format(time.RFC3339)), colorSize(humanize.Bytes(uint64(f.Size()))), colorName(f.Name()))
				}
			}
			w.Flush()
		} else {
			fmt.Fprintf(w, "- [ OTA ASSETS FILES ] %s\n\n", strings.Repeat("-", 50))
			for _, f := range ota.Files() {
				if !f.IsDir() {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", colorMode(f.Mode()), colorModTime(f.ModTime().Format(time.RFC3339)), colorSize(humanize.Bytes(uint64(f.Size()))), colorName(f.Path()))
				}
			}
			w.Flush()
		}

		return nil
	},
}
