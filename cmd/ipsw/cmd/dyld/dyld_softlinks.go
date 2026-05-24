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
package dyld

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DyldCmd.AddCommand(dyldSoftlinksCmd)
	dyldSoftlinksCmd.Flags().String("image", "", "Image path/name in the DSC")
	dyldSoftlinksCmd.Flags().String("filter", "", "Regex filter for softlink symbol/helper names")
	dyldSoftlinksCmd.Flags().StringP("format", "O", "tsv", "Output format: tsv, jsonl")
	viper.BindPFlag("dyld.softlinks.image", dyldSoftlinksCmd.Flags().Lookup("image"))
	viper.BindPFlag("dyld.softlinks.filter", dyldSoftlinksCmd.Flags().Lookup("filter"))
	viper.BindPFlag("dyld.softlinks.format", dyldSoftlinksCmd.Flags().Lookup("format"))
}

// dyldSoftlinksCmd represents the softlinks command.
var dyldSoftlinksCmd = &cobra.Command{
	Use:     "softlinks <DSC>",
	Aliases: []string{"softlink"},
	Short:   "Enumerate SOFT_LINK globals in a DSC image",
	Args:    cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getDSCs(toComplete), cobra.ShellCompDirectiveDefault
	},
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		dscPath := filepath.Clean(args[0])
		if _, err := os.Lstat(dscPath); err != nil {
			return fmt.Errorf("file %s does not exist", dscPath)
		}

		f, err := dyld.Open(dscPath)
		if err != nil {
			return err
		}
		defer f.Close()

		records, err := dyld.SoftLinks(f, dyld.SoftLinkConfig{
			Image:  viper.GetString("dyld.softlinks.image"),
			Filter: viper.GetString("dyld.softlinks.filter"),
		})
		if err != nil {
			return err
		}
		return printSoftLinks(records, viper.GetString("dyld.softlinks.format"))
	},
}

func printSoftLinks(records []dyld.SoftLinkRecord, format string) error {
	switch format {
	case "tsv", "":
		return printSoftLinksTSV(records)
	case "jsonl":
		enc := json.NewEncoder(os.Stdout)
		for _, record := range records {
			if err := enc.Encode(record); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("--format must be one of: tsv, jsonl")
	}
}

func printSoftLinksTSV(records []dyld.SoftLinkRecord) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	fmt.Fprintln(w, "symbol\tglobal-addr\tinit-fn-addr\tonce-addr\tframework-lib-addr\tglobal\tinit-fn\tonce\tframework-lib")
	for _, record := range records {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			record.Symbol,
			softLinkAddr(record.GlobalAddr),
			softLinkAddr(record.InitFuncAddr),
			softLinkAddr(record.OnceAddr),
			softLinkAddr(record.FrameworkLibAddr),
			record.GlobalName,
			record.InitFuncName,
			record.OnceName,
			record.FrameworkLibName,
		)
	}
	return w.Flush()
}

func softLinkAddr(addr uint64) string {
	if addr == 0 {
		return ""
	}
	return fmt.Sprintf("%#x", addr)
}
