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
	"strings"
	"text/tabwriter"

	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DyldCmd.AddCommand(WebKitIPCCmd)
	WebKitIPCCmd.Flags().String("image", "/System/Library/Frameworks/WebKit.framework/WebKit", "WebKit image path/name in the DSC")
	WebKitIPCCmd.Flags().StringP("format", "O", "tsv", "Output format: tsv, jsonl")
	WebKitIPCCmd.Flags().Bool("raw", false, "Include plausible Receiver_Message strings not backed by Messages::* symbols")
	WebKitIPCCmd.Flags().Bool("symbol-fallback", false, "Include Messages::* symbol records that do not have a description string")
	WebKitIPCCmd.Flags().String("receiver", "", "Filter receiver names by substring or glob")
	WebKitIPCCmd.Flags().String("message", "", "Filter message names by substring or glob")
	viper.BindPFlag("dyld.webkit-ipc.image", WebKitIPCCmd.Flags().Lookup("image"))
	viper.BindPFlag("dyld.webkit-ipc.format", WebKitIPCCmd.Flags().Lookup("format"))
	viper.BindPFlag("dyld.webkit-ipc.raw", WebKitIPCCmd.Flags().Lookup("raw"))
	viper.BindPFlag("dyld.webkit-ipc.symbol-fallback", WebKitIPCCmd.Flags().Lookup("symbol-fallback"))
	viper.BindPFlag("dyld.webkit-ipc.receiver", WebKitIPCCmd.Flags().Lookup("receiver"))
	viper.BindPFlag("dyld.webkit-ipc.message", WebKitIPCCmd.Flags().Lookup("message"))
}

// WebKitIPCCmd represents the webkit-ipc command
var WebKitIPCCmd = &cobra.Command{
	Use:     "webkit-ipc <DSC>",
	Aliases: []string{"wipc"},
	Short:   "Dump compiled WebKit IPC message names from a DSC",
	Hidden:  true,
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

		records, err := dyld.WebKitIPCMessages(f, dyld.WebKitIPCConfig{
			Image:             viper.GetString("dyld.webkit-ipc.image"),
			IncludeRawStrings: viper.GetBool("dyld.webkit-ipc.raw"),
			IncludeSymbolOnly: viper.GetBool("dyld.webkit-ipc.symbol-fallback"),
			ReceiverPattern:   viper.GetString("dyld.webkit-ipc.receiver"),
			MessagePattern:    viper.GetString("dyld.webkit-ipc.message"),
		})
		if err != nil {
			return err
		}

		return printWebKitIPC(records, viper.GetString("dyld.webkit-ipc.format"))
	},
}

func printWebKitIPC(records []dyld.WebKitIPCRecord, format string) error {
	switch format {
	case "tsv", "":
		return printWebKitIPCTSV(records)
	case "jsonl":
		return printWebKitIPCJSONL(records)
	default:
		return fmt.Errorf("--format must be one of: tsv, jsonl")
	}
}

func printWebKitIPCTSV(records []dyld.WebKitIPCRecord) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	fmt.Fprintln(w, "addr\treceiver\tmessage\tname\thandler\targ-types\tworkqueue\tsection\tsource\tsymbol")
	for _, record := range records {
		addr := ""
		if record.Address != 0 {
			addr = fmt.Sprintf("%#x", record.Address)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%t\t%s\t%s\t%s\n",
			addr,
			record.Receiver,
			record.Message,
			record.Name,
			record.HandlerClass,
			strings.Join(record.ArgTypes, "; "),
			record.WorkQueue,
			record.Section,
			record.Source,
			webKitIPCSymbolField(record),
		)
	}
	return w.Flush()
}

func webKitIPCSymbolField(record dyld.WebKitIPCRecord) string {
	if len(record.Symbols) > 0 {
		return strings.Join(record.Symbols, "; ")
	}
	return record.Symbol
}

func printWebKitIPCJSONL(records []dyld.WebKitIPCRecord) error {
	enc := json.NewEncoder(os.Stdout)
	for _, record := range records {
		if err := enc.Encode(record); err != nil {
			return err
		}
	}
	return nil
}
