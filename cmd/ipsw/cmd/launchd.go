/*
Copyright © 2018-2026 blacktop

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
	"strings"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/launchd"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(launchdCmd)

	launchdCmd.Flags().String("format", "jsonl", "Output format (only jsonl is supported)")
	launchdCmd.Flags().String("pem-db", "", "AEA PEM DB JSON file path")

	viper.BindPFlag("launchd.format", launchdCmd.Flags().Lookup("format"))
	viper.BindPFlag("launchd.pem-db", launchdCmd.Flags().Lookup("pem-db"))

	launchdCmd.MarkZshCompPositionalArgumentFile(1, "*.ipsw", "*.zip")
}

var launchdCmd = &cobra.Command{
	Use:           "launchd <IPSW>",
	Short:         "Stream launchd and XPC plist metadata as JSONL",
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	SilenceUsage:  true,
	Hidden:        true,
	Example: heredoc.Doc(`
		# Emit launchd/XPC metadata from an IPSW as deterministic JSONL
		❯ ipsw launchd iPhone18,1_26.0_23A5276f_Restore.ipsw --format jsonl`),
	RunE: func(cmd *cobra.Command, args []string) error {
		format := strings.ToLower(strings.TrimSpace(viper.GetString("launchd.format")))
		if format != "jsonl" {
			return fmt.Errorf("unsupported --format %q (only \"jsonl\" is supported)", viper.GetString("launchd.format"))
		}

		records, skipped, err := launchd.WalkIPSW(expandPath(args[0]), &launchd.IPSWConfig{
			PemDB: viper.GetString("launchd.pem-db"),
		})
		for _, skip := range skipped {
			log.Warnf("skipped %s volume: %v", skip.Volume, skip.Err)
		}
		if err != nil {
			return err
		}

		out, err := launchd.EncodeJSONL(records)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(out)
		return err
	},
}
