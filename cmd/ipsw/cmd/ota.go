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
	"strings"
	"text/tabwriter"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/ota"
	"github.com/dustin/go-humanize"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(otaCmd)

	otaCmd.Flags().BoolP("info", "i", false, "Display OTA Info")
	otaCmd.Flags().BoolP("list", "l", false, "List files in OTA")
	// otaCmd.Flags().BoolP("remote", "r", false, "Extract from URL")
	// otaCmd.Flags().BoolP("single", "s", false, "Stop after first match") TODO: impliment this
	otaCmd.Flags().StringP("output", "o", "", "Folder to extract files to")

	viper.BindPFlag("ota.info", otaCmd.Flags().Lookup("info"))
	viper.BindPFlag("ota.list", otaCmd.Flags().Lookup("list"))
	// viper.BindPFlag("ota.remote", otaCmd.Flags().Lookup("remote"))
	viper.BindPFlag("ota.output", otaCmd.Flags().Lookup("output"))

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

		otaPath := filepath.Clean(args[0])

		if _, err := os.Stat(otaPath); os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", otaPath)
		}

		showInfo := viper.GetBool("ota.info")
		listFiles := viper.GetBool("ota.list")
		// remote := viper.GetBool("ota.remote")
		output := viper.GetString("ota.output")

		if showInfo {
			pIPSW, err := info.Parse(otaPath)
			if err != nil {
				return errors.Wrap(err, "failed to extract and parse IPSW info")
			}
			fmt.Println("\n[OTA Info]")
			fmt.Println("==========")
			fmt.Println(pIPSW)

			return nil
		}

		if listFiles {
			log.Info("Listing files in OTA zip...")
			files, err := ota.ListZip(otaPath)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.DiscardEmptyColumns)
			fmt.Fprintf(w, "[ OTA zip files ] %s\n", strings.Repeat("-", 50))
			for _, f := range files {
				if !f.IsDir() {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", f.Mode(), f.ModTime().Format(time.RFC3339), humanize.Bytes(uint64(f.Size())), f.Name())
				}
			}
			w.Flush()

			log.Info("Listing files in OTA payload...")
			utils.Indent(log.Warn, 1)("(OTA might not actually contain all these files if it is a partial update file)")
			fmt.Fprintf(w, "\n[ payload files ] %s\n", strings.Repeat("-", 50))
			files, err = ota.List(otaPath)
			if err != nil {
				return err
			}
			for _, f := range files {
				if !f.IsDir() {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", f.Mode(), f.ModTime().Format(time.RFC3339), humanize.Bytes(uint64(f.Size())), f.Name())
				}
			}
			w.Flush()
		}

		if len(args) > 1 {
			pattern := args[1]
			if len(pattern) == 0 {
				return fmt.Errorf("you must supply an extract regex pattern")
			}
			log.Infof("Extracting files that match %#v", pattern)
			return ota.Extract(otaPath, pattern, output)
		}

		return nil
	},
}
