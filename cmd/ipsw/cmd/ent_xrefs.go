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
	"path/filepath"
	"strings"

	"github.com/MakeNowJust/heredoc/v2"
	entxrefs "github.com/blacktop/ipsw/pkg/ent/xrefs"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	entCmd.AddCommand(entXrefsCmd)

	entXrefsCmd.Flags().String("dsc", "", "Path to dyld_shared_cache to scan")
	entXrefsCmd.Flags().String("format", "jsonl", "Output format (only jsonl is supported)")

	viper.BindPFlag("ent.xrefs.dsc", entXrefsCmd.Flags().Lookup("dsc"))
	viper.BindPFlag("ent.xrefs.format", entXrefsCmd.Flags().Lookup("format"))
}

var entXrefsCmd = &cobra.Command{
	Use:   "xrefs [KERNELCACHE] [DSC]",
	Short: "Find entitlement-check callsites in a kernelcache and/or DSC",
	Example: heredoc.Doc(`
		# Scan a kernelcache and matching dyld shared cache
		❯ ipsw ent xrefs kernelcache.release.iphone dyld_shared_cache_arm64e --format jsonl

		# Kernel-only
		❯ ipsw ent xrefs kernelcache.release.iphone --format jsonl

		# DSC-only
	❯ ipsw ent xrefs --dsc dyld_shared_cache_arm64e --format jsonl`),
	Args:          cobra.RangeArgs(0, 2),
	SilenceErrors: true,
	SilenceUsage:  true,
	Hidden:        true,
	RunE: func(cmd *cobra.Command, args []string) error {
		format := strings.ToLower(strings.TrimSpace(viper.GetString("ent.xrefs.format")))
		if format != "jsonl" {
			return fmt.Errorf("unsupported --format %q (only \"jsonl\" is supported)", format)
		}

		kernelPath, dscPath, err := parseEntXrefsInputs(args, viper.GetString("ent.xrefs.dsc"))
		if err != nil {
			return err
		}

		records, err := entxrefs.Scan(entxrefs.Config{
			Kernelcache: kernelPath,
			DSC:         dscPath,
			Stderr:      os.Stderr,
		})
		if err != nil {
			if errors.Is(err, entxrefs.ErrNoTargetSymbols) {
				return fmt.Errorf("no entitlement-check target symbols found in supplied input(s)")
			}
			return err
		}
		return entxrefs.WriteJSONL(os.Stdout, records)
	},
}

func parseEntXrefsInputs(args []string, dscFlag string) (string, string, error) {
	var kernelPath string
	var dscPath string
	if dscFlag != "" {
		dscPath = filepath.Clean(dscFlag)
		if len(args) > 1 {
			return "", "", fmt.Errorf("expected at most one positional KERNELCACHE when --dsc is set")
		}
		if len(args) == 1 {
			kernelPath = filepath.Clean(args[0])
		}
	} else {
		switch len(args) {
		case 0:
			return "", "", fmt.Errorf("provide KERNELCACHE, DSC, or --dsc DSC")
		case 1:
			kernelPath = filepath.Clean(args[0])
		case 2:
			kernelPath = filepath.Clean(args[0])
			dscPath = filepath.Clean(args[1])
		}
	}
	if kernelPath == "" && dscPath == "" {
		return "", "", fmt.Errorf("provide KERNELCACHE, DSC, or --dsc DSC")
	}
	return kernelPath, dscPath, nil
}
