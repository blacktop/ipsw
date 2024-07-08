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
	"fmt"

	"github.com/apex/log"
	kcmd "github.com/blacktop/ipsw/internal/commands/kernel"
	"github.com/blacktop/ipsw/pkg/signature"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	KernelcacheCmd.AddCommand(kernelSymbolicateCmd)

	kernelSymbolicateCmd.Flags().StringP("signatures", "s", "", "Path to signatures folder")
	viper.BindPFlag("kernel.symbolicate.signatures", kernelSymbolicateCmd.Flags().Lookup("signatures"))
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

		var sigs []*signature.Signature
		if viper.IsSet("kernel.symbolicate.signatures") {
			sigs, err = kcmd.ParseSignatures(viper.GetString("kernel.symbolicate.signatures"))
			if err != nil {
				return fmt.Errorf("failed to parse signatures: %v", err)
			}
		}

		// symbolicate kernelcache
		return kcmd.Symbolicate(args[0], sigs)
	},
}
