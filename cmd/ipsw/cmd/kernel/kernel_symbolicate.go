/*
Copyright © 2025 blacktop

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
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/demangle"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/signature"
	"github.com/invopop/jsonschema"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	KernelcacheCmd.AddCommand(kernelSymbolicateCmd)

	kernelSymbolicateCmd.Flags().BoolP("flat", "f", false, "Output results in flat file '.syms' format")
	kernelSymbolicateCmd.Flags().BoolP("json", "j", false, "Output results in JSON format")
	kernelSymbolicateCmd.Flags().BoolP("quiet", "q", false, "Do NOT display logging")
	kernelSymbolicateCmd.Flags().Bool("test", false, "Test symbol matches")
	kernelSymbolicateCmd.Flags().MarkHidden("test")
	kernelSymbolicateCmd.Flags().Bool("schema", false, "Generate JSON schema")
	kernelSymbolicateCmd.Flags().MarkHidden("schema")
	kernelSymbolicateCmd.Flags().StringP("signatures", "s", "", "Path to signatures folder")
	kernelSymbolicateCmd.Flags().Uint64P("lookup", "l", 0, "Lookup a symbol by address")
	kernelSymbolicateCmd.Flags().StringP("output", "o", "", "Folder to write files to")
	kernelSymbolicateCmd.Flags().StringP("arch", "a", "", "Which architecture to use for fat/universal MachO")
	kernelSymbolicateCmd.MarkFlagDirname("output")
	viper.BindPFlag("kernel.symbolicate.flat", kernelSymbolicateCmd.Flags().Lookup("flat"))
	viper.BindPFlag("kernel.symbolicate.json", kernelSymbolicateCmd.Flags().Lookup("json"))
	viper.BindPFlag("kernel.symbolicate.quiet", kernelSymbolicateCmd.Flags().Lookup("quiet"))
	viper.BindPFlag("kernel.symbolicate.test", kernelSymbolicateCmd.Flags().Lookup("test"))
	viper.BindPFlag("kernel.symbolicate.schema", kernelSymbolicateCmd.Flags().Lookup("schema"))
	viper.BindPFlag("kernel.symbolicate.signatures", kernelSymbolicateCmd.Flags().Lookup("signatures"))
	viper.BindPFlag("kernel.symbolicate.lookup", kernelSymbolicateCmd.Flags().Lookup("lookup"))
	viper.BindPFlag("kernel.symbolicate.output", kernelSymbolicateCmd.Flags().Lookup("output"))
	viper.BindPFlag("kernel.symbolicate.arch", kernelSymbolicateCmd.Flags().Lookup("arch"))
}

// kernelSymbolicateCmd represents the symbolicate command
var kernelSymbolicateCmd = &cobra.Command{
	Use:           "symbolicate",
	Aliases:       []string{"sym"},
	Short:         "Symbolicate kernelcache",
	Args:          cobra.MinimumNArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) (err error) {

		quiet := viper.GetBool("kernel.symbolicate.quiet")
		selectedArch := viper.GetString("kernel.symbolicate.arch")

		output := viper.GetString("kernel.symbolicate.output")
		if output == "" {
			output = filepath.Dir(filepath.Clean(args[0]))
		}

		if viper.GetBool("kernel.symbolicate.schema") {
			schema := jsonschema.Reflect(&signature.Symbolicator{})
			schema.Description = "ipsw Symbolicator definition file"
			bts, err := json.MarshalIndent(schema, "	", "	")
			if err != nil {
				return fmt.Errorf("failed to create jsonschema: %w", err)
			}
			if err := writeSymbolicatorSchema(viper.GetString("kernel.symbolicate.output"), output, bts); err != nil {
				return err
			}
			return nil
		}

		if viper.GetUint64("kernel.symbolicate.lookup") != 0 {
			log.Info("Looking up symbol")
			smap := signature.NewSymbolMap()
			if err := smap.LoadJSON(args[0]); err != nil {
				return fmt.Errorf("failed to load symbol map: %v", err)
			}
			addr := viper.GetUint64("kernel.symbolicate.lookup")
			if sym, ok := smap[addr]; ok {
				fmt.Printf("%#x %s\n", addr, sym)
				return nil
			}
			return fmt.Errorf("symbol not found at address %#x", addr)
		}

		var sigs []signature.Symbolicator
		if sigDir := viper.GetString("kernel.symbolicate.signatures"); sigDir != "" {
			log.Info("Parsing Signatures")
			sigs, err = signature.Parse(sigDir)
			if err != nil {
				return fmt.Errorf("failed to parse signatures: %v", err)
			}
		}

		smap := signature.NewSymbolMap()
		m, err := mcmd.OpenMachO(args[0], selectedArch)
		if err != nil {
			return fmt.Errorf("failed to open kernelcache: %v", err)
		}
		defer m.Close()

		// symbolicate kernelcache
		log.WithField("kernelcache", filepath.Base(args[0])).Info("Symbolicating...")
		if err := smap.SymbolicateMachO(m.File, filepath.Base(args[0]), sigs, quiet); err != nil {
			return fmt.Errorf("failed to symbolicate kernelcache: %v", err)
		}

		// test the accuracy of the symbolication on the source KDK material
		if viper.GetBool("kernel.symbolicate.test") {
			match := 0
			miss := 0
			log.Warn("Testing symbol matches")
			dsym, err := mcmd.OpenMachO(args[0]+".dSYM/Contents/Resources/DWARF/"+filepath.Base(args[0]), selectedArch)
			if err != nil {
				return fmt.Errorf("failed to open kernelcache: %v", err)
			}
			defer dsym.Close()
			for addr, sym := range smap {
				matched, actual := matchKernelTestSymbol(dsym.File, addr, sym)
				if matched {
					match++
					if !quiet {
						log.Infof("✅ Symbol '%s' matches", sym)
					}
				} else {
					if len(actual) == 0 {
						actual = append(actual, "<not found>")
					}
					utils.Indent(log.Error, 2)(
						fmt.Sprintf("❌ Symbol at address %#x mismatch: matched %s, actual %s", addr, sym, strings.Join(actual, ", ")),
					)
					miss++
				}
			}
			utils.Indent(log.Info, 2)(
				fmt.Sprintf("Matched %d symbols, Missed %d symbols: %.4f%%", match, miss, 100*float64(match)/float64(len(smap))),
			)
			return nil
		}

		/* JSON OUTPUT */

		if viper.GetBool("kernel.symbolicate.json") {
			jdat, err := json.Marshal(smap)
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
			for addr, sym := range smap {
				fmt.Fprintf(f, "%#x %s\n", addr, sym)
			}
			return nil
		}

		fmt.Printf("%s symbols:\n", filepath.Base(args[0]))
		for addr, sym := range smap {
			fmt.Printf("%#x %s\n", addr, sym)
		}

		return nil
	},
}

var kernelSymbolSuffixRE = regexp.MustCompile(`\.\d+$`)

const vtableHeaderSize uint64 = 16

func matchKernelTestSymbol(m *macho.File, addr uint64, expected string) (bool, []string) {
	actual := make([]string, 0, 4)
	seen := make(map[string]struct{})

	for _, candidate := range kernelTestLookupAddrs(addr, expected) {
		syms, err := m.FindAddressSymbols(candidate)
		if err != nil {
			continue
		}
		for _, sym := range syms {
			if _, ok := seen[sym.Name]; !ok {
				actual = append(actual, sym.Name)
				seen[sym.Name] = struct{}{}
			}
			if kernelSymbolMatches(expected, sym.Name) {
				return true, actual
			}
		}
	}

	slices.Sort(actual)
	return false, actual
}

func kernelTestLookupAddrs(addr uint64, expected string) []uint64 {
	addrs := []uint64{addr}
	if strings.HasPrefix(expected, "vtable for ") && addr >= vtableHeaderSize {
		addrs = append(addrs, addr-vtableHeaderSize)
	}
	return addrs
}

func kernelSymbolMatches(expected, actual string) bool {
	raw := kernelSymbolSuffixRE.ReplaceAllString(actual, "")
	raw = strings.TrimPrefix(raw, "__kernelrpc")

	switch {
	case strings.TrimLeft(expected, "_") == strings.TrimLeft(raw, "_"):
		return true
	case strings.TrimSuffix(expected, "_trap") == strings.TrimLeft(raw, "_"):
		return true
	}

	demangled := strings.TrimPrefix(demangle.Do(raw, false, false), "__kernelrpc")
	if demangled == expected {
		return true
	}
	if strings.HasPrefix(demangled, expected+"(") {
		return true
	}

	return false
}

func writeSymbolicatorSchema(outputFlag, outputDir string, data []byte) error {
	if outputFlag == "" || outputFlag == "-" {
		fmt.Println(string(data))
		return nil
	}

	schemaFile := filepath.Join(outputDir, "symbolicator.schema.json")
	log.Infof("Writing JSON schema to %s", schemaFile)
	return os.WriteFile(schemaFile, data, 0o644)
}
