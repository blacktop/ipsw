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
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/pkg/kernelcache/cpp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	KernelcacheCmd.AddCommand(vtableCmd)

	vtableCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	vtableCmd.Flags().StringP("class", "c", "", "Show vtable for specific class")
	vtableCmd.Flags().BoolP("methods", "m", false, "Show method details for each class")
	vtableCmd.Flags().BoolP("inheritance", "i", false, "Show inheritance hierarchy")
	vtableCmd.Flags().IntP("limit", "l", 0, "Limit number of classes to display (0 = all)")

	viper.BindPFlag("kernel.vtable.json", vtableCmd.Flags().Lookup("json"))
	viper.BindPFlag("kernel.vtable.class", vtableCmd.Flags().Lookup("class"))
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
		# Limit number of classes displayed
		❯ ipsw kernel vtable --limit 10 kernelcache.release.iPhone17,1
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

		cls, err := cpp.GetClasses(m)
		if err != nil {
			return fmt.Errorf("failed to get classes from kernelcache: %v", err)
		}

		if len(cls) == 0 {
			log.Warn("No classes discovered")
			return nil
		}

		log.Infof("Discovered %d C++ classes", len(cls))

		// Filter by specific class if requested
		if className := viper.GetString("kernel.vtable.class"); className != "" {
			filtered := make([]cpp.ClassMeta, 0, 1)
			for _, class := range cls {
				if strings.Contains(class.Name, className) {
					filtered = append(filtered, class)
				}
			}
			if len(filtered) == 0 {
				return fmt.Errorf("class containing '%s' not found", className)
			}
			cls = filtered
		}

		// Apply limit if specified
		if limit := viper.GetInt("kernel.vtable.limit"); limit > 0 && limit < len(cls) {
			cls = cls[:limit]
		}

		// Output results
		if viper.GetBool("kernel.vtable.json") {
			data, err := json.Marshal(cls)
			if err != nil {
				return err
			}
			fmt.Println(string(data))
			return nil
		}

		// Pretty print results
		fmt.Printf("\nDiscovered %d C++ classes:\n\n", len(cls))
		showMethods := viper.GetBool("kernel.vtable.methods")
		showInheritance := viper.GetBool("kernel.vtable.inheritance")

		for _, class := range cls {
			fmt.Println(class.String())
			// Show inheritance hierarchy if requested
			if showInheritance && class.SuperClass != nil {
				printInheritanceChain(&class, 1)
			}
			// Show vtable and methods if requested
			if showMethods && class.VtableAddr != 0 {
				for _, method := range class.Methods {
					fmt.Printf("  %s\n", method.String())
				}
			}
		}

		return nil
	},
}

// printInheritanceChain recursively prints the inheritance hierarchy
func printInheritanceChain(class *cpp.ClassMeta, depth int) {
	if class.SuperClass == nil {
		return
	}
	indent := strings.Repeat("  ", depth)
	fmt.Printf("%s╰─ inherits from: %s", indent, class.SuperClass.Name)
	if class.SuperClass.Bundle != "" && class.SuperClass.Bundle != class.Bundle {
		fmt.Printf(" (%s)", class.SuperClass.Bundle)
	}
	fmt.Println()
	printInheritanceChain(class.SuperClass, depth+1)
}
