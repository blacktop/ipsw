/*
Copyright © 2018-2023 blacktop

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

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	KernelcacheCmd.AddCommand(kernelVersionCmd)
	kernelVersionCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	kernelVersionCmd.MarkZshCompPositionalArgumentFile(1, "kernelcache.*")
	// kernelVersionCmd.ValidArgsFunction = func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	// 	return []string{"ipsw", "zip"}, cobra.ShellCompDirectiveFilterFileExt
	// }
}

// kernelVersionCmd represents the version command
var kernelVersionCmd = &cobra.Command{
	Use:           "version",
	Aliases:       []string{"v"},
	Short:         "Dump kernelcache version",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		asJSON, _ := cmd.Flags().GetBool("json")

		machoPath := filepath.Clean(args[0])

		m, err := macho.Open(machoPath)
		if err != nil {
			return err
		}

		kv, err := kernelcache.GetVersion(m)
		if err != nil {
			return err
		}

		if asJSON {
			o, err := json.Marshal(kv)
			if err != nil {
				return err
			}
			fmt.Println(string(o))
			return nil
		}

		fmt.Println(kv)

		return nil
	},
}
