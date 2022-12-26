/*
Copyright © 2018-2022 blacktop

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

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	KernelcacheCmd.AddCommand(kernelSandboxCmd)
	kernelSandboxCmd.Flags().BoolP("diff", "d", false, "Diff two kernel's sandbox operations")
	kernelSandboxCmd.MarkZshCompPositionalArgumentFile(1, "kernelcache*")
}

// kernelSandboxCmd represents the kernelSandboxCmd command
var kernelSandboxCmd = &cobra.Command{
	Use:   "sbopts",
	Short: "List kernel sandbox operations",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		diff, _ := cmd.Flags().GetBool("diff")

		kcPath := filepath.Clean(args[0])

		if _, err := os.Stat(kcPath); os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", args[0])
		}

		m, err := macho.Open(kcPath)
		if err != nil {
			return err
		}
		defer m.Close()

		sbOpts, err := kernelcache.GetSandboxOpts(m)
		if err != nil {
			return err
		}

		if diff {
			if len(args) < 2 {
				return fmt.Errorf("please provide two kernelcache files to diff")
			}

			kcPath2 := filepath.Clean(args[1])

			if _, err := os.Stat(kcPath2); os.IsNotExist(err) {
				return fmt.Errorf("file %s does not exist", args[1])
			}

			m2, err := macho.Open(kcPath2)
			if err != nil {
				return err
			}
			defer m2.Close()

			sbOpts2, err := kernelcache.GetSandboxOpts(m2)
			if err != nil {
				return err
			}

			out, err := utils.GitDiff(strings.Join(sbOpts, "\n"), strings.Join(sbOpts2, "\n"))
			if err != nil {
				return err
			}
			if len(out) == 0 {
				log.Info("No differences found")
			} else {
				log.Info("Differences found")
				fmt.Println(out)
			}
		} else {
			title := fmt.Sprintf("Sandbox Operations (%d)", len(sbOpts))
			fmt.Println(title)
			fmt.Println(strings.Repeat("=", len(title)))
			for _, opt := range sbOpts {
				fmt.Println(opt)
			}
		}

		return nil
	},
}
