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

	"github.com/MakeNowJust/heredoc/v2"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/pkg/kernel/kalloctype"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	KernelcacheCmd.AddCommand(kernelKallocCmd)

	kernelKallocCmd.Flags().Bool("collisions", false, "Emit only kalloc type collisions grouped by size and signature")
	kernelKallocCmd.Flags().StringP("arch", "a", "", "Which architecture to use for fat/universal MachO")

	_ = viper.BindPFlag("kernel.kalloc.collisions", kernelKallocCmd.Flags().Lookup("collisions"))
	_ = viper.BindPFlag("kernel.kalloc.arch", kernelKallocCmd.Flags().Lookup("arch"))
}

var kernelKallocCmd = &cobra.Command{
	Use:     "kalloc <kernelcache>",
	Aliases: []string{"ktv", "kalloc-type"},
	Short:   "Emit kalloc_type views as deterministic JSONL",
	Example: heredoc.Doc(`
		# Emit kalloc_type and kalloc_type_var views
		❯ ipsw kernel kalloc kernelcache.release.iPhone18,1

		# Emit only groups whose type names collide by size and signature
		❯ ipsw kernel kalloc kernelcache.release.iPhone18,1 --collisions`),
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	SilenceUsage:  true,
	Hidden:        true,
	RunE: func(cmd *cobra.Command, args []string) error {
		kernelPath := filepath.Clean(args[0])
		m, err := mcmd.OpenMachO(kernelPath, viper.GetString("kernel.kalloc.arch"))
		if err != nil {
			return fmt.Errorf("open kernelcache: %w", err)
		}
		defer func() {
			_ = m.Close()
		}()

		records, err := kalloctype.Scan(m.File)
		if err != nil {
			return err
		}
		if viper.GetBool("kernel.kalloc.collisions") {
			return kalloctype.WriteCollisionJSONL(os.Stdout, kalloctype.Collisions(records))
		}
		return kalloctype.WriteJSONL(os.Stdout, records)
	},
}
