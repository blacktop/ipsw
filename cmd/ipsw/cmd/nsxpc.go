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
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/blacktop/ipsw/pkg/nsxpc"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(nsxpcCmd)

	nsxpcCmd.Flags().String("format", "jsonl", "Output format (only jsonl is supported)")
	viper.BindPFlag("nsxpc.format", nsxpcCmd.Flags().Lookup("format"))
}

var nsxpcCmd = &cobra.Command{
	Use:           "nsxpc <DSC>",
	Short:         "Stream NSXPC interface and secure-coding facts from a DSC as JSONL",
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	SilenceUsage:  true,
	Hidden:        true,
	Example: heredoc.Doc(`
		# Emit NSXPC facts from a dyld shared cache as deterministic JSONL
		❯ ipsw nsxpc dyld_shared_cache_arm64e --format jsonl`),
	RunE: func(cmd *cobra.Command, args []string) error {
		format := strings.ToLower(strings.TrimSpace(viper.GetString("nsxpc.format")))
		if format != "jsonl" {
			return fmt.Errorf("unsupported --format %q (only \"jsonl\" is supported)", viper.GetString("nsxpc.format"))
		}
		records, err := nsxpc.Scan(nsxpc.Config{
			DSC:    expandPath(args[0]),
			Stderr: os.Stderr,
		})
		if err != nil {
			switch {
			case errors.Is(err, nsxpc.ErrNoObjCProtocols):
				return fmt.Errorf("DSC has no __objc_protolist protocol metadata")
			case errors.Is(err, nsxpc.ErrNoResolvedInterface):
				return fmt.Errorf("no resolved NSXPCInterface interfaceWithProtocol: callsites found")
			default:
				return err
			}
		}
		return nsxpc.WriteJSONL(os.Stdout, records)
	},
}
