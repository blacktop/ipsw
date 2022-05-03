//go:build cgo

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
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/pkg/sandbox"
	"github.com/fatih/color"
	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/spf13/cobra"
)

func init() {
	kernelcacheCmd.AddCommand(kernelSandboxCmd)
	kernelSandboxCmd.Flags().BoolP("diff", "d", false, "Diff two kernel's sandbox operations")
	kernelSandboxCmd.MarkZshCompPositionalArgumentFile(1, "kernelcache*")
}

// kernelSandboxCmd represents the kernelSandboxCmd command
var kernelSandboxCmd = &cobra.Command{
	Use:           "sbopts",
	Short:         "List kernel sandbox operations",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
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

		sb, err := sandbox.NewSandbox(m)
		if err != nil {
			return fmt.Errorf("failed to create kernelcache sandbox parser: %v", err)
		}

		sbOpts, err := sb.GetOperations()
		if err != nil {
			return fmt.Errorf("failed to get sandbox operations: %s", err)
		}

		if diff {
			in := color.New(color.FgGreen).Add(color.Bold)
			dl := color.New(color.FgRed).Add(color.Bold)

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

			sb2, err := sandbox.NewSandbox(m2)
			if err != nil {
				return fmt.Errorf("failed to create kernelcache sandbox parser: %v", err)
			}

			sbOpts2, err := sb2.GetOperations()
			if err != nil {
				return fmt.Errorf("failed to get sandbox operations: %s", err)
			}

			sb1OUT := strings.Join(sbOpts, "\n")
			sb2OUT := strings.Join(sbOpts2, "\n")

			dmp := diffmatchpatch.New()

			diffs := dmp.DiffMain(sb1OUT, sb2OUT, true)
			if len(diffs) > 2 {
				diffs = dmp.DiffCleanupSemantic(diffs)
				diffs = dmp.DiffCleanupEfficiency(diffs)
			}

			if len(diffs) == 1 {
				if diffs[0].Type == diffmatchpatch.DiffEqual {
					log.Info("No differences found")
				}
			} else {
				log.Info("Differences found")
				if Verbose {
					fmt.Println(dmp.DiffPrettyText(diffs))
				} else {
					for _, d := range diffs {
						if d.Type == diffmatchpatch.DiffInsert {
							in.Println(d.Text)
						} else if d.Type == diffmatchpatch.DiffDelete {
							dl.Println(d.Text)
						}
					}
				}
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
