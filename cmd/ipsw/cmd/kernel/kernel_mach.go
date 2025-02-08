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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	KernelcacheCmd.AddCommand(kernelMachCmd)
	kernelMachCmd.MarkZshCompPositionalArgumentFile(1, "kernelcache*")
}

// kernelMachCmd represents the mach command
var kernelMachCmd = &cobra.Command{
	Use:           "mach",
	Aliases:       []string{"mt"},
	Short:         "Dump kernelcache mach_traps",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		machoPath := filepath.Clean(args[0])

		if strings.Contains(machoPath, "development") {
			log.Warn("development kernelcache detected: 'MACH_ASSERT=1' so 'mach_trap_t' has an extra 'const char *mach_trap_name' field which will throw off the parsing of the mach_traps table")
		}

		m, err := macho.Open(machoPath)
		if err != nil {
			return err
		}
		defer m.Close()

		machTraps, err := kernelcache.GetMachTrapTable(m)
		if err != nil {
			return err
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		for idx, mtrap := range machTraps {
			fmt.Fprintf(w, "%d\t%s\n", idx, mtrap)
		}
		w.Flush()

		return nil
	},
}
