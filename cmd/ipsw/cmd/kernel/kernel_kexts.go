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
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/colors"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	KernelcacheCmd.AddCommand(kextsCmd)
	kextsCmd.Flags().BoolP("diff", "d", false, "Diff two kernel's kexts")
	kextsCmd.Flags().BoolP("json", "j", false, "Output kexts as JSON")
	kextsCmd.Flags().StringP("arch", "a", "", "Which architecture to use for fat/universal MachO")
	viper.BindPFlag("kernel.kexts.diff", kextsCmd.Flags().Lookup("diff"))
	viper.BindPFlag("kernel.kexts.json", kextsCmd.Flags().Lookup("json"))
	viper.BindPFlag("kernel.kexts.arch", kextsCmd.Flags().Lookup("arch"))
	kextsCmd.MarkZshCompPositionalArgumentFile(1, "kernelcache*")
}

// kextsCmd represents the kexts command
var kextsCmd = &cobra.Command{
	Use:           "kexts <kernelcache>",
	Aliases:       []string{"k"},
	Short:         "List kernel extensions",
	Args:          cobra.MinimumNArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		// flags
		selectedArch := viper.GetString("kernel.kexts.arch")
		// validate flags
		if viper.GetBool("kernel.kexts.diff") && viper.GetBool("kernel.kexts.json") {
			return fmt.Errorf("cannot use --diff and --json flags together")
		}

		if viper.GetBool("kernel.kexts.diff") {
			if len(args) < 2 {
				return fmt.Errorf("please provide two kernelcache files to diff")
			}

			m1, err := mcmd.OpenMachO(args[0], selectedArch)
			if err != nil {
				return err
			}
			defer func() {
				if err := m1.Close(); err != nil {
					log.WithError(err).Error("failed to close file: " + args[0])
				}
			}()

			kout1, err := kernelcache.KextList(m1.File, true)
			if err != nil {
				return err
			}

			m2, err := mcmd.OpenMachO(args[1], selectedArch)
			if err != nil {
				return err
			}
			defer func() {
				if err := m2.Close(); err != nil {
					log.WithError(err).Error("failed to close file: " + args[1])
				}
			}()

			kout2, err := kernelcache.KextList(m2.File, true)
			if err != nil {
				return err
			}

			out, err := utils.GitDiff(
				strings.Join(kout1, "\n"),
				strings.Join(kout2, "\n"),
				&utils.GitDiffConfig{Color: colors.Active(),Tool: viper.GetString("diff-tool")})
			if err != nil {
				return err
			}
			if len(out) == 0 {
				log.Info("No differences found")
				return nil
			}
			log.Info("Differences found")
			fmt.Println(out)
		} else {
			m, err := mcmd.OpenMachO(args[0], selectedArch)
			if err != nil {
				return err
			}
			defer func() {
				if err := m.Close(); err != nil {
					log.WithError(err).Error("failed to close file: " + args[0])
				}
			}()

			if viper.GetBool("kernel.kexts.json") {
				kexts, err := kernelcache.KextJSON(m.File)
				if err != nil {
					return err
				}
				fmt.Println(kexts)
			} else {
				kout, err := kernelcache.KextList(m.File, false)
				if err != nil {
					return err
				}
				log.WithField("count", len(kout)).Info("Kexts")
				for _, k := range kout {
					fmt.Println(k)
				}
			}
		}

		return nil
	},
}
