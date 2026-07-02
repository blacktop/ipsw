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
package kernel

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/pkg/kernelcache/pacx"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	KernelcacheCmd.AddCommand(kernelPacXrefsCmd)

	// Long-flags-only: avoid the -a/-e/-i/-l/-o/-c shorthands the parent binds.
	kernelPacXrefsCmd.Flags().String("format", "jsonl", "Output format (only jsonl is supported)")
	kernelPacXrefsCmd.Flags().String("arch", "", "Which architecture to use for fat/universal MachO")
	kernelPacXrefsCmd.Flags().String("func", "", "Only emit call sites reaching this target function address")
	kernelPacXrefsCmd.Flags().String("callsite", "", "Only emit the record for this call-site address")
	kernelPacXrefsCmd.Flags().Bool("include-unresolved", false, "Emit call sites with zero matching candidates")

	viper.BindPFlag("kernel.pac-xrefs.format", kernelPacXrefsCmd.Flags().Lookup("format"))
	viper.BindPFlag("kernel.pac-xrefs.arch", kernelPacXrefsCmd.Flags().Lookup("arch"))
	viper.BindPFlag("kernel.pac-xrefs.func", kernelPacXrefsCmd.Flags().Lookup("func"))
	viper.BindPFlag("kernel.pac-xrefs.callsite", kernelPacXrefsCmd.Flags().Lookup("callsite"))
	viper.BindPFlag("kernel.pac-xrefs.include-unresolved", kernelPacXrefsCmd.Flags().Lookup("include-unresolved"))
}

var kernelPacXrefsCmd = &cobra.Command{
	Use:    "pac-xrefs <kernelcache>",
	Short:  "Resolve authenticated C++ virtual calls to their candidate target functions",
	Hidden: true,
	Example: heredoc.Doc(`
		# Emit all resolved authenticated virtual-call edges as JSONL
		❯ ipsw kernel pac-xrefs kernelcache.release.iPhone17,1 --format jsonl

		# Only the record for one call site
		❯ ipsw kernel pac-xrefs kernelcache.release.iPhone17,1 --callsite 0xfffffe0007123456

		# Every call site that reaches one target function
		❯ ipsw kernel pac-xrefs kernelcache.release.iPhone17,1 --func 0xfffffe0007abcdef`),
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	SilenceUsage:  true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		if err := validatePacXrefsFormat(viper.GetString("kernel.pac-xrefs.format")); err != nil {
			return err
		}
		funcAddr, funcSet, err := parseOptionalAddr(viper.GetString("kernel.pac-xrefs.func"), "--func")
		if err != nil {
			return err
		}
		callsiteAddr, callsiteSet, err := parseOptionalAddr(viper.GetString("kernel.pac-xrefs.callsite"), "--callsite")
		if err != nil {
			return err
		}
		if funcSet && callsiteSet {
			return fmt.Errorf("--func and --callsite are mutually exclusive")
		}

		m, err := mcmd.OpenMachO(filepath.Clean(args[0]), viper.GetString("kernel.pac-xrefs.arch"))
		if err != nil {
			return fmt.Errorf("open kernelcache: %w", err)
		}
		defer m.Close()

		records, err := pacx.ScanKernelcache(m.File, pacx.ScanConfig{
			Name:              filepath.Base(args[0]),
			IncludeUnresolved: viper.GetBool("kernel.pac-xrefs.include-unresolved"),
			Stderr:            os.Stderr,
		})
		if err != nil {
			return err
		}

		switch {
		case callsiteSet:
			records = filterByCallsite(records, callsiteAddr)
		case funcSet:
			records = pacx.CallSitesFromFunc(records, funcAddr)
		}
		return pacx.WriteJSONL(os.Stdout, records)
	},
}

// validatePacXrefsFormat rejects any output format other than jsonl.
func validatePacXrefsFormat(raw string) error {
	if format := strings.ToLower(strings.TrimSpace(raw)); format != "jsonl" {
		return fmt.Errorf("unsupported --format %q (only \"jsonl\" is supported)", raw)
	}
	return nil
}

// parseOptionalAddr parses an optional 0x-hex or decimal address flag. The second
// return value reports whether the flag was set.
func parseOptionalAddr(raw, flag string) (uint64, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false, nil
	}
	addr, err := strconv.ParseUint(raw, 0, 64)
	if err != nil {
		return 0, false, fmt.Errorf("invalid %s address %q: %w", flag, raw, err)
	}
	return addr, true, nil
}

func filterByCallsite(records []pacx.PacRecord, addr uint64) []pacx.PacRecord {
	out := make([]pacx.PacRecord, 0, 1)
	for _, rec := range records {
		if rec.Callsite == addr {
			out = append(out, rec)
		}
	}
	return out
}
