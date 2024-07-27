/*
Copyright © 2024 blacktop

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
	otaLsCmd.AddCommand(otaLsPayloadCmd)
}

// otaLsPayloadCmd represents the payload command
var otaLsPayloadCmd = &cobra.Command{
	Use:           "payload <OTA> <PAYLOAD>",
	Aliases:       []string{"p"},
	Short:         "List contents of a payloadv2 file",
	Args:          cobra.ExactArgs(2),
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

		payload, err := ota.Open(filepath.Clean(args[1]))
		if err != nil {
			return fmt.Errorf("failed to open payload file: %v", err)
		}
		defer payload.Close()

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.DiscardEmptyColumns)
		fmt.Fprintf(w, "- [ PAYLOAD ASSETS FILES ] %s\n\n", strings.Repeat("-", 50))
		for _, f := range payload.File {
			if !f.Mod.IsDir() {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", f.Entry.Mod, f.Entry.Mtm.Format(time.RFC3339), humanize.Bytes(uint64(f.Entry.Size)), f.Entry.Path)
			}
		}
		w.Flush()

		return nil
	},
}
