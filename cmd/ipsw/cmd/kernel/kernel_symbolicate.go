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
package kernel

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/pkg/signature"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	KernelcacheCmd.AddCommand(kernelSymbolicateCmd)

	kernelSymbolicateCmd.Flags().BoolP("flat", "f", false, "Output results in flat file '.syms' format")
	kernelSymbolicateCmd.Flags().BoolP("json", "j", false, "Output results in JSON format")
	kernelSymbolicateCmd.Flags().BoolP("quiet", "q", false, "Don't display logging")
	kernelSymbolicateCmd.Flags().Bool("test", false, "Test symbol matches")
	kernelSymbolicateCmd.Flags().MarkHidden("test")
	kernelSymbolicateCmd.Flags().StringP("signatures", "s", "", "Path to signatures folder")
	kernelSymbolicateCmd.MarkFlagRequired("signatures")
	kernelSymbolicateCmd.Flags().StringP("output", "o", "", "Folder to write files to")
	kernelSymbolicateCmd.MarkFlagDirname("output")
	viper.BindPFlag("kernel.symbolicate.flat", kernelSymbolicateCmd.Flags().Lookup("flat"))
	viper.BindPFlag("kernel.symbolicate.json", kernelSymbolicateCmd.Flags().Lookup("json"))
	viper.BindPFlag("kernel.symbolicate.quiet", kernelSymbolicateCmd.Flags().Lookup("quiet"))
	viper.BindPFlag("kernel.symbolicate.test", kernelSymbolicateCmd.Flags().Lookup("test"))
	viper.BindPFlag("kernel.symbolicate.signatures", kernelSymbolicateCmd.Flags().Lookup("signatures"))
	viper.BindPFlag("kernel.symbolicate.output", kernelSymbolicateCmd.Flags().Lookup("output"))
}

// kernelSymbolicateCmd represents the symbolicate command
var kernelSymbolicateCmd = &cobra.Command{
	Use:           "symbolicate",
	Aliases:       []string{"sym"},
	Short:         "Symbolicate kernelcache",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	Hidden:        true,
	RunE: func(cmd *cobra.Command, args []string) (err error) {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		quiet := viper.GetBool("kernel.symbolicate.quiet")

		output := viper.GetString("kernel.symbolicate.output")
		if output == "" {
			output = filepath.Dir(filepath.Clean(args[0]))
		}

		log.Info("Parsing Signatures")
		sigs, err := signature.Parse(viper.GetString("kernel.symbolicate.signatures"))
		if err != nil {
			return fmt.Errorf("failed to parse signatures: %v", err)
		}

		// symbolicate kernelcache
		symMap := make(map[uint64]string)
		goodsig := false
		log.WithField("kernelcache", filepath.Base(args[0])).Info("Symbolicating...")
		for _, sig := range sigs {
			syms, err := signature.Symbolicate(args[0], sig, quiet)
			if err != nil {
				if errors.Is(err, signature.ErrUnsupportedTarget) ||
					errors.Is(err, signature.ErrUnsupportedVersion) {
					continue
				}
				return fmt.Errorf("failed to symbolicate kernelcache: %v", err)
			}
			maps.Copy(symMap, syms)
			goodsig = true
		}

		if !goodsig {
			return fmt.Errorf("no valid signatures found for kernelcache (let author know and we can add them)")
		}

		if viper.GetBool("kernel.symbolicate.test") {
			match := 0
			miss := 0
			log.Warn("Testing symbol matches")
			m, err := macho.Open(args[0] + ".dSYM/Contents/Resources/DWARF/" + filepath.Base(args[0]))
			if err != nil {
				return fmt.Errorf("failed to open kernelcache: %v", err)
			}
			defer m.Close()
			for addr, sym := range symMap {
				syms, err := m.FindAddressSymbols(addr)
				if err != nil {
					log.WithError(err).Errorf("symbol '%s' with addr %#x not found in kernelcache", sym, addr)
					continue
				}
				for _, s := range syms {
					log.Debug(s.String(m))
					if before, ok := strings.CutSuffix(s.Name, sym); ok {
						if before != "_" && before != "" {
							log.Warnf("Unexpected symbol prefix: %s", before)
						}
						log.Infof("✅ Symbol '%s' matches", sym)
						match++
					} else {
						log.Errorf("❌ Symbol at address %#x mismatch: matched %s, actual %s", addr, sym, s.Name)
						miss++
					}
				}
			}
			log.Infof("Matched %d symbols, missed %d symbols", match, miss)
			return nil
		}

		/* JSON OUTPUT */

		if viper.GetBool("kernel.symbolicate.json") {
			jdat, err := json.Marshal(symMap)
			if err != nil {
				return fmt.Errorf("failed to marshal symbol map: %v", err)
			}
			fname := filepath.Join(output, filepath.Base(args[0])+".symbols.json")
			log.Infof("Writing symbols as JSON to %s", fname)
			return os.WriteFile(fname, jdat, 0o644)
		}

		/* FLAT FILE OUTPUT */

		if viper.GetBool("kernel.symbolicate.flat") {
			fname := filepath.Join(output, filepath.Base(args[0])+".syms")
			log.Infof("Writing symbols to %s", fname)
			f, err := os.Create(fname)
			if err != nil {
				return fmt.Errorf("failed to create symbols file: %v", err)
			}
			defer f.Close()
			for addr, sym := range symMap {
				fmt.Fprintf(f, "%#x %s\n", addr, sym)
			}
			return nil
		}

		fmt.Printf("%s symbols:\n", filepath.Base(args[0]))
		for addr, sym := range symMap {
			fmt.Printf("%#x %s\n", addr, sym)
		}

		return nil
	},
}
