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
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	KernelcacheCmd.AddCommand(syscallCmd)
	syscallCmd.Flags().BoolP("gen", "g", false, "Generate syscall table data gzip file")
	syscallCmd.Flags().StringP("output", "o", "", "Output gzip file")
	syscallCmd.Flags().StringP("arch", "a", "", "Which architecture to use for fat/universal MachO")
	syscallCmd.MarkZshCompPositionalArgumentFile(1, "kernelcache*")
	viper.BindPFlag("kernel.syscall.gen", syscallCmd.Flags().Lookup("gen"))
	viper.BindPFlag("kernel.syscall.output", syscallCmd.Flags().Lookup("output"))
	viper.BindPFlag("kernel.syscall.arch", syscallCmd.Flags().Lookup("arch"))
}

// syscallCmd represents the syscall command
var syscallCmd = &cobra.Command{
	Use:           "syscall",
	Aliases:       []string{"sc"},
	Short:         "Dump kernelcache syscalls",
	Args:          cobra.MinimumNArgs(0),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		gen := viper.GetBool("kernel.syscall.gen")
		output := viper.GetString("kernel.syscall.output")
		selectedArch := viper.GetString("kernel.syscall.arch")

		if gen {
			return kernelcache.ParseSyscallFiles(output)
		}

		if len(args) == 0 {
			return fmt.Errorf("no kernelcache files specified")
		}

		machoPath := filepath.Clean(args[0])

		m, err := mcmd.OpenMachO(machoPath, selectedArch)
		if err != nil {
			return err
		}
		defer m.Close()

		syscalls, err := kernelcache.GetSyscallTable(m.File)
		if err != nil {
			return err
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		for _, syscall := range syscalls {
			fmt.Fprintf(w, "%s\n", syscall)
		}
		w.Flush()

		return nil
	},
}
