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
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/syms"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(symbolsCmd)

	symbolsCmd.Flags().Bool("json", true, "Emit symbols as JSONL (one JSON object per line)")
	symbolsCmd.Flags().Bool("dyld", false, "Include dyld_shared_cache dylib symbols")
	symbolsCmd.Flags().Bool("kernel", false, "Include kernelcache/KEXT symbols")
	symbolsCmd.Flags().Bool("filesystem", false, "Include file system Mach-O symbols")
	symbolsCmd.Flags().String("signatures", "", "Path to kernel symbolication signatures directory")
	symbolsCmd.Flags().String("pem-db", "", "AEA pem DB JSON file")
	symbolsCmd.Flags().StringP("output", "o", "", "Output file path (\"-\" or unset for stdout)")

	viper.BindPFlag("symbols.json", symbolsCmd.Flags().Lookup("json"))
	viper.BindPFlag("symbols.dyld", symbolsCmd.Flags().Lookup("dyld"))
	viper.BindPFlag("symbols.kernel", symbolsCmd.Flags().Lookup("kernel"))
	viper.BindPFlag("symbols.filesystem", symbolsCmd.Flags().Lookup("filesystem"))
	viper.BindPFlag("symbols.signatures", symbolsCmd.Flags().Lookup("signatures"))
	viper.BindPFlag("symbols.pem-db", symbolsCmd.Flags().Lookup("pem-db"))
	viper.BindPFlag("symbols.output", symbolsCmd.Flags().Lookup("output"))

	symbolsCmd.MarkZshCompPositionalArgumentFile(1, "*.ipsw", "*.zip")
}

// symbolsCmd represents the symbols command
var symbolsCmd = &cobra.Command{
	Use:     "symbols <IPSW>",
	Aliases: []string{"syms"},
	Short:   "Emit IPSW symbols as JSONL",
	Long: `Emit every symbol in an IPSW as newline-delimited JSON (JSONL).

The stream is emitted in this order: one "ipsw" line, then for each image an
"image" line immediately followed by that image's "symbol" lines. Each
dyld_shared_cache also emits a one-time "dsc" line carrying shared_region_start,
which its dylib images reference via dsc_uuid.

Kernel and KEXT symbol addresses are bit-63-cleared exactly as the ipswd symbol
database stores them, so a server backed by this output returns byte-identical
results to the daemon.`,
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	Hidden:        true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		// Default to all sources when none are explicitly selected.
		kernel := viper.GetBool("symbols.kernel")
		dyld := viper.GetBool("symbols.dyld")
		filesystem := viper.GetBool("symbols.filesystem")
		if !kernel && !dyld && !filesystem {
			kernel, dyld, filesystem = true, true, true
		}

		ipswPath := filepath.Clean(args[0])
		if _, err := os.Stat(ipswPath); err != nil {
			return fmt.Errorf("file %s does not exist: %w", ipswPath, err)
		}

		out := os.Stdout
		if output := viper.GetString("symbols.output"); output != "" && output != "-" {
			f, err := os.Create(output)
			if err != nil {
				return fmt.Errorf("failed to create output file %s: %w", output, err)
			}
			defer f.Close()
			out = f
		}

		return syms.ScanJSONL(&syms.JSONLConfig{
			IPSW:       ipswPath,
			PemDB:      viper.GetString("symbols.pem-db"),
			SigsDir:    viper.GetString("symbols.signatures"),
			Kernel:     kernel,
			DSC:        dyld,
			FileSystem: filesystem,
		}, out)
	},
}
