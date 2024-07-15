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
	"fmt"
	"maps"
	"os"
	"path/filepath"

	"github.com/apex/log"
	kcmd "github.com/blacktop/ipsw/internal/commands/kernel"
	"github.com/blacktop/ipsw/pkg/signature"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	KernelcacheCmd.AddCommand(kernelSymbolicateCmd)

	kernelSymbolicateCmd.Flags().BoolP("json", "j", false, "Output results in JSON format")
	kernelSymbolicateCmd.Flags().StringP("signatures", "s", "", "Path to signatures folder")
	kernelSymbolicateCmd.Flags().StringP("output", "o", "", "Folder to write files to")
	kernelSymbolicateCmd.MarkFlagDirname("output")
	viper.BindPFlag("kernel.symbolicate.json", kernelSymbolicateCmd.Flags().Lookup("json"))
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

		var sigs []*signature.Symbolicator
		if viper.IsSet("kernel.symbolicate.signatures") {
			sigs, err = kcmd.ParseSignatures(viper.GetString("kernel.symbolicate.signatures"))
			if err != nil {
				return fmt.Errorf("failed to parse signatures: %v", err)
			}
		}

		// symbolicate kernelcache
		symMap := make(map[uint64]string)
		for _, sig := range sigs {
			syms, err := kcmd.Symbolicate(args[0], sig)
			if err != nil {
				return fmt.Errorf("failed to symbolicate kernelcache: %v", err)
			}
			maps.Copy(symMap, syms)
		}

		if viper.GetBool("kernel.symbolicate.json") {
			jdat, err := json.Marshal(symMap)
			if err != nil {
				return fmt.Errorf("failed to marshal symbol map: %v", err)
			}

			if viper.IsSet("kernel.symbolicate.output") {
				fname := filepath.Join(viper.GetString("kernel.symbolicate.output"), "symbols.json")
				log.Infof("Writing symbols as JSON to %s", fname)
				return os.WriteFile(fname, jdat, 0o644)
			}

			fmt.Println(string(jdat))

			return nil
		}

		if viper.IsSet("kernel.symbolicate.output") {
			fname := filepath.Join(viper.GetString("kernel.symbolicate.output"), "symbols.map")
			log.Infof("Writing symbols to %s", fname)
			f, err := os.Create(fname)
			if err != nil {
				return fmt.Errorf("failed to create symbols file: %v", err)
			}
			defer f.Close()
			for addr, sym := range symMap {
				fmt.Fprintf(f, "%#x %s\n", addr, sym)
			}
		} else {
			fmt.Printf("%s symbols:\n", filepath.Base(args[0]))
			for addr, sym := range symMap {
				fmt.Printf("%#x %s\n", addr, sym)
			}
		}

		return nil
	},
}
