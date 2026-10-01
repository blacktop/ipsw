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
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(symbolsCmd)

	symbolsCmd.Flags().Bool("json", true, "Emit symbols as JSONL (one JSON object per line)")
	symbolsCmd.Flags().Bool("dyld", false, "Include dyld_shared_cache dylib symbols")
	symbolsCmd.Flags().Bool("kernel", false, "Include kernelcache/KEXT symbols")
	symbolsCmd.Flags().Bool("filesystem", false, "Include file system Mach-O symbols")
	symbolsCmd.Flags().Bool("facts", false, "Emit versioned per-image comparison facts")
	symbolsCmd.Flags().StringSlice("facts-boards", nil,
		"Scan shared components once for this exact board subset (requires --facts)")
	symbolsCmd.Flags().String("signatures", "", "Path to kernel symbolication signatures directory")
	symbolsCmd.Flags().String("pem-db", "", "AEA pem DB JSON file")
	symbolsCmd.Flags().String("device", "", "Device product type or board for IPSW selection (e.g. Mac18,5 or j873gap)")
	symbolsCmd.Flags().StringP("output", "o", "", "Output file path (\"-\" or unset for stdout)")

	viper.BindPFlag("symbols.json", symbolsCmd.Flags().Lookup("json"))
	viper.BindPFlag("symbols.dyld", symbolsCmd.Flags().Lookup("dyld"))
	viper.BindPFlag("symbols.kernel", symbolsCmd.Flags().Lookup("kernel"))
	viper.BindPFlag("symbols.filesystem", symbolsCmd.Flags().Lookup("filesystem"))
	viper.BindPFlag("symbols.facts", symbolsCmd.Flags().Lookup("facts"))
	viper.BindPFlag("symbols.facts-boards", symbolsCmd.Flags().Lookup("facts-boards"))
	viper.BindPFlag("symbols.signatures", symbolsCmd.Flags().Lookup("signatures"))
	viper.BindPFlag("symbols.pem-db", symbolsCmd.Flags().Lookup("pem-db"))
	viper.BindPFlag("symbols.device", symbolsCmd.Flags().Lookup("device"))
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

Each image occurrence (UUID, kind, path, text range, arch, DSC) is emitted once
per scan, even when the IPSW carries it in several containers (for example a
KEXT shared by a release and a research kernelcache).

Kernel and KEXT symbol addresses are bit-63-cleared exactly as the ipswd symbol
database stores them, so a server backed by this output returns byte-identical
results to the daemon. Kernels found on the file system
(/System/Library/Kernels/kernel*, /System/Library/KernelCollections/*.kc) are
emitted the same way: kind "kernel", canonical /System/Library/... path, and
bit-63-cleared text and symbol ranges.

With --facts, a "comparison_facts_collection_start" line follows the "ipsw" line.
One versioned "comparison_facts" line is emitted per FAT slice, before that
file's image/symbol lines (if it gets any), including UUID-less Mach-Os and
deduplicated occurrences (for example a KEXT shared by release and research
kernelcaches, or a volume mounted under two labels). Kernelcaches are selected
from BuildManifest KernelCache components and named from the device-filtered
metadata, so with --device a kernelcache image path can differ from the same
scan without --facts. A final "comparison_facts_complete" line is written only
after every requested source has been scanned successfully.

With --facts --facts-boards board1,board2, collection schema 4 binds the exact
selected board subset and scans each distinct BuildManifest component once.
Every facts occurrence and DSC header carries its exact component_path, and
successful coverage includes per-component counts (including empty components).
This mode requires JSON output and cannot be combined with --device.`,
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

		var factsBoards []string
		if cmd.Flags().Changed("facts-boards") || viper.IsSet("symbols.facts-boards") {
			factsBoards = viper.GetStringSlice("symbols.facts-boards")
			if factsBoards == nil {
				factsBoards = []string{}
			}
		}
		ipswPath := filepath.Clean(args[0])
		cfg := &syms.JSONLConfig{
			Device: viper.GetString("symbols.device"), IPSW: ipswPath,
			PemDB: viper.GetString("symbols.pem-db"), SigsDir: viper.GetString("symbols.signatures"),
			Kernel: kernel, DSC: dyld, FileSystem: filesystem,
			Facts: viper.GetBool("symbols.facts"), FactsBoards: factsBoards,
		}
		// Reject invalid flag combinations before any source I/O.
		if factsBoards != nil && !viper.GetBool("symbols.json") {
			return fmt.Errorf("--facts-boards requires --json")
		}
		if err := syms.ValidateFactsBoardsOptions(cfg); err != nil {
			return err
		}
		if _, err := os.Stat(ipswPath); err != nil {
			return fmt.Errorf("file %s does not exist: %w", ipswPath, err)
		}

		// Validate the selection before creating or truncating the output file.
		inf, err := info.Parse(ipswPath)
		if err != nil {
			return err
		}
		cfg.Info = inf
		if factsBoards != nil {
			err = syms.ValidateFactsSelection(cfg)
		} else if dyld || filesystem {
			_, err = inf.SelectDevice(cfg.Device)
		} else {
			_, err = inf.ForDevice(cfg.Device)
		}
		if err != nil {
			return err
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

		return syms.ScanJSONL(cfg, out)
	},
}
