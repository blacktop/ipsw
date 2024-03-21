/*
Copyright © 2018-2024 blacktop

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
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	KernelcacheCmd.AddCommand(kextsCmd)
	kextsCmd.Flags().BoolP("diff", "d", false, "Diff two kernel's kexts")
	kextsCmd.MarkZshCompPositionalArgumentFile(1, "kernelcache*")
}

// kextsCmd represents the kexts command
var kextsCmd = &cobra.Command{
	Use:     "kexts <kernelcache>",
	Aliases: []string{"k"},
	Short:   "List kernel extentions",
	Args:    cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		diff, _ := cmd.Flags().GetBool("diff")

		if _, err := os.Stat(args[0]); os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", args[0])
		}

		if diff {
			if len(args) < 2 {
				return fmt.Errorf("please provide two kernelcache files to diff")
			}

			kout1, err := kernelcache.KextList(args[0], true)
			if err != nil {
				return err
			}
			kout2, err := kernelcache.KextList(args[1], true)
			if err != nil {
				return err
			}

			out, err := utils.GitDiff(
				strings.Join(kout1, "\n"),
				strings.Join(kout2, "\n"),
				&utils.GitDiffConfig{Color: viper.GetBool("color") && !viper.GetBool("no-color"), Tool: viper.GetString("diff-tool")})
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
			kout, err := kernelcache.KextList(args[0], false)
			if err != nil {
				return err
			}
			log.WithField("count", len(kout)).Info("Kexts")
			for _, k := range kout {
				fmt.Println(k)
			}
		}

		return nil
	},
}
