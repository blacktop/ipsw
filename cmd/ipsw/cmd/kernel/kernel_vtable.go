/*
Copyright © 2018-2025 blacktop

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
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	colorClass  = color.New(color.Bold, color.FgHiMagenta).SprintFunc()
	colorBundle = color.New(color.Bold, color.FgHiBlue).SprintFunc()
	colorAddr   = color.New(color.Faint).SprintfFunc()
)

func init() {
	KernelcacheCmd.AddCommand(vtableCmd)

	vtableCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	vtableCmd.Flags().StringP("class", "c", "", "Show vtable for specific class")
	vtableCmd.Flags().StringP("symbols", "s", "", "Load external symbol map file")
	vtableCmd.Flags().StringP("output", "o", "", "Output symbol map to file")
	vtableCmd.Flags().Bool("methods", false, "Show method details for each class")
	vtableCmd.Flags().Bool("inheritance", false, "Show inheritance hierarchy")
	vtableCmd.Flags().Int("limit", 0, "Limit number of classes to display (0 = all)")

	viper.BindPFlag("kernel.vtable.json", vtableCmd.Flags().Lookup("json"))
	viper.BindPFlag("kernel.vtable.class", vtableCmd.Flags().Lookup("class"))
	viper.BindPFlag("kernel.vtable.symbols", vtableCmd.Flags().Lookup("symbols"))
	viper.BindPFlag("kernel.vtable.output", vtableCmd.Flags().Lookup("output"))
	viper.BindPFlag("kernel.vtable.methods", vtableCmd.Flags().Lookup("methods"))
	viper.BindPFlag("kernel.vtable.inheritance", vtableCmd.Flags().Lookup("inheritance"))
	viper.BindPFlag("kernel.vtable.limit", vtableCmd.Flags().Lookup("limit"))
}

// vtableCmd represents the vtable command
var vtableCmd = &cobra.Command{
	Use:   "vtable <kernelcache>",
	Short: "Extract and symbolicate C++ vtables from kernelcache",
	Example: heredoc.Doc(`
		# Basic vtable extraction
		❯ ipsw kernel vtable kernelcache.release.iPhone17,1
		# Show vtable for specific class
		❯ ipsw kernel vtable -c IOService kernelcache.release.iPhone17,1
		# Show method details and inheritance
		❯ ipsw kernel vtable --methods --inheritance kernelcache.release.iPhone17,1
		# Load external symbol map for better naming
		❯ ipsw kernel vtable -s symbol_map.txt kernelcache.release.iPhone17,1
		# Export symbol map for use with other tools
		❯ ipsw kernel vtable -o vtable_symbols.txt kernelcache.release.iPhone17,1
		# JSON output for scripting
		❯ ipsw kernel vtable --json kernelcache.release.iPhone17,1`),
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		m, err := macho.Open(filepath.Clean(args[0]))
		if err != nil {
			return fmt.Errorf("failed to open kernelcache: %v", err)
		}
		defer m.Close()

		vs := kernelcache.NewVtableSymbolicator(m)

		// Load external symbol map if provided
		if symbolsPath := viper.GetString("kernel.vtable.symbols"); symbolsPath != "" {
			symbolMap, err := loadSymbolMap(symbolsPath)
			if err != nil {
				return fmt.Errorf("failed to load symbol map: %v", err)
			}
			vs.LoadSymbolMap(symbolMap)
			log.Infof("Loaded %d symbols from %s", len(symbolMap), symbolsPath)
		}

		// Perform vtable symbolication
		log.Info("Starting vtable symbolication...")
		if err := vs.SymbolicateVtables(); err != nil {
			return fmt.Errorf("vtable symbolication failed: %v", err)
		}

		// Get results
		classes := vs.GetClasses()
		if len(classes) == 0 {
			log.Warn("No classes discovered")
			return nil
		}
		log.Infof("Discovered %d C++ classes", len(classes))

		// Filter by specific class if requested
		if className := viper.GetString("kernel.vtable.class"); className != "" {
			if class, exists := vs.GetClassByName(className); exists {
				classes = []*kernelcache.ClassMeta{class}
			} else {
				return fmt.Errorf("class '%s' not found", className)
			}
		}

		// Apply limit if specified
		if limit := viper.GetInt("kernel.vtable.limit"); limit > 0 && limit < len(classes) {
			classes = classes[:limit]
		}

		// Output results
		if viper.GetBool("kernel.vtable.json") {
			data, err := json.Marshal(classes)
			if err != nil {
				return err
			}
			fmt.Println(string(data))
			return nil
		}

		outputText(classes, viper.GetBool("kernel.vtable.methods"), viper.GetBool("kernel.vtable.inheritance"))

		// Export symbol map if requested
		if outputPath := viper.GetString("kernel.vtable.output"); outputPath != "" {
			if err := exportSymbolMap(vs.GetSymbolMap(), outputPath); err != nil {
				return fmt.Errorf("failed to export symbol map: %v", err)
			}
			log.Infof("Exported symbol map to %s", outputPath)
		}

		return nil
	},
}

// loadSymbolMap loads an external symbol map file
func loadSymbolMap(filePath string) (map[uint64]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	symbolMap := make(map[uint64]string)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		// Parse address (supports both 0x prefix and plain hex)
		addrStr := strings.TrimPrefix(parts[0], "0x")
		addr, err := strconv.ParseUint(addrStr, 16, 64)
		if err != nil {
			log.Warnf("Invalid address in symbol map: %s", parts[0])
			continue
		}

		// Symbol name is the rest of the line
		symbol := strings.Join(parts[1:], " ")
		symbolMap[addr] = symbol
	}

	return symbolMap, scanner.Err()
}

// exportSymbolMap exports the discovered symbols to a file
func exportSymbolMap(symbolMap map[uint64]string, filePath string) error {
	// Create output directory if needed
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return err
	}

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write header
	fmt.Fprintf(file, "# Vtable symbols extracted by ipsw\n")
	fmt.Fprintf(file, "# Format: <address> <symbol_name>\n")
	fmt.Fprintf(file, "\n")

	// Write symbols sorted by address
	addresses := make([]uint64, 0, len(symbolMap))
	for addr := range symbolMap {
		addresses = append(addresses, addr)
	}

	// Sort addresses
	sort.Slice(addresses, func(i, j int) bool {
		return addresses[i] < addresses[j]
	})

	for _, addr := range addresses {
		fmt.Fprintf(file, "%#x %s\n", addr, symbolMap[addr])
	}

	return nil
}

// outputText outputs the results in human-readable text format
func outputText(classes []*kernelcache.ClassMeta, showMethods, showInheritance bool) {
	var out strings.Builder
	out.WriteString(fmt.Sprintf("\nDiscovered %d C++ classes:\n\n", len(classes)))
	for _, class := range classes {
		// Class header
		out.WriteString(fmt.Sprintf("%-70s", colorClass(class.Name)))
		if class.Size > 0 && viper.GetBool("verbose") {
			out.WriteString(fmt.Sprintf(" (size: %d bytes)", class.Size))
		}

		// Show inheritance if requested and available
		if showInheritance && class.SuperClass != nil {
			out.WriteString(fmt.Sprintf("  (super: %s)", colorClass(class.SuperClass.Name)))
		}

		// Show addresses
		if class.MetaPtr != 0 {
			out.WriteString(fmt.Sprintf("\tmeta-class: %s", colorAddr(fmt.Sprintf("%#x", class.MetaPtr))))
		}
		if class.VtableAddr != 0 {
			out.WriteString(fmt.Sprintf("\tvtable: %s", colorAddr(fmt.Sprintf("%#x", class.VtableAddr))))
		}

		// Show methods if requested
		if showMethods && len(class.Methods) > 0 {
			out.WriteString(fmt.Sprintf("\n  methods (%d):\n", len(class.Methods)))
			for _, method := range class.Methods {
				out.WriteString(fmt.Sprintf("    [%2d] %s  %s\n", method.Index, colorAddr(fmt.Sprintf("%#x", method.Address)), method.Name))
			}
		} else if len(class.Methods) > 0 {
			out.WriteString(fmt.Sprintf("  methods: %d (use --methods to show details)\n", len(class.Methods)))
		}

		if class.Bundle != "" {
			out.WriteString(fmt.Sprintf("\t%s", colorBundle(class.Bundle)))
		}

		out.WriteString("\n")
	}
	fmt.Println(out.String())
}
