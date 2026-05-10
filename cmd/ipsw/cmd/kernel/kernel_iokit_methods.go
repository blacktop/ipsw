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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/MakeNowJust/heredoc/v2"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/pkg/kernel/iokit"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	KernelcacheCmd.AddCommand(kernelIOKitMethodsCmd)

	kernelIOKitMethodsCmd.Flags().String("format", "jsonl", "Output format (only jsonl is supported)")
	kernelIOKitMethodsCmd.Flags().StringP("arch", "a", "", "Which architecture to use for fat/universal MachO")

	viper.BindPFlag("kernel.iokit-methods.format", kernelIOKitMethodsCmd.Flags().Lookup("format"))
	viper.BindPFlag("kernel.iokit-methods.arch", kernelIOKitMethodsCmd.Flags().Lookup("arch"))
}

var kernelIOKitMethodsCmd = &cobra.Command{
	Use:   "iokit-methods <kernelcache>",
	Short: "Emit IOUserClient external method tables as deterministic JSONL",
	Example: heredoc.Doc(`
		# Emit IOKit method and service-client records
		❯ ipsw kernel iokit-methods kernelcache.release.iPhone17,1 --format jsonl`),
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	SilenceUsage:  true,
	Hidden:        true,
	RunE: func(cmd *cobra.Command, args []string) error {
		format := strings.ToLower(strings.TrimSpace(viper.GetString("kernel.iokit-methods.format")))
		if format != "jsonl" {
			return fmt.Errorf("unsupported --format %q (only \"jsonl\" is supported)", format)
		}

		kernelPath := filepath.Clean(args[0])
		m, err := mcmd.OpenMachO(kernelPath, viper.GetString("kernel.iokit-methods.arch"))
		if err != nil {
			return fmt.Errorf("open kernelcache: %w", err)
		}
		defer m.Close()

		records, err := iokit.Scan(m.File, iokit.Config{
			Kernelcache: kernelPath,
			Stderr:      os.Stderr,
		})
		if err != nil {
			if errors.Is(err, iokit.ErrNoIOUserClients) {
				return fmt.Errorf("no IOUserClient subclasses discovered")
			}
			return err
		}
		return iokit.WriteJSONL(os.Stdout, records)
	},
}
