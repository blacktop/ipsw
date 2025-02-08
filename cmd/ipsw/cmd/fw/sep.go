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
package fw

import (
	"fmt"
	"path/filepath"

	"github.com/apex/log"
	fwcmd "github.com/blacktop/ipsw/internal/commands/fw"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/sep"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// NOTE:
//   Firmware/all_flash/sep-firmware.d83.RELEASE.im4p
//   Firmware/all_flash/sep-patches.d83.im4p

func init() {
	FwCmd.AddCommand(fwSepCmd)

	fwSepCmd.Flags().BoolP("info", "i", false, "Print info")
	fwSepCmd.Flags().StringP("output", "o", "", "Folder to extract files to")
	fwSepCmd.MarkFlagDirname("output")
	viper.BindPFlag("fw.sep.info", fwSepCmd.Flags().Lookup("info"))
	viper.BindPFlag("fw.sep.output", fwSepCmd.Flags().Lookup("output"))
}

// fwSepCmd represents the sep command
var fwSepCmd = &cobra.Command{
	Use:     "sep",
	Aliases: []string{"s", "sepfw"},
	Short:   "🚧 Dump MachOs",
	Args:    cobra.ExactArgs(1),
	Hidden:  true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		showInfo := viper.GetBool("fw.sep.info")
		output := viper.GetString("fw.sep.output")

		if showInfo {
			sp, err := sep.Parse(filepath.Clean(args[0]))
			if err != nil {
				return fmt.Errorf("failed to parse sep firmware '%s': %v", filepath.Clean(args[0]), err)
			}
			fmt.Println(sp)
		} else {
			log.Info("Extracting Sep Firmware")
			out, err := fwcmd.SplitSepFW(filepath.Clean(args[0]), output)
			if err != nil {
				return fmt.Errorf("failed to extract files from sep firmware '%s': %v", filepath.Clean(args[0]), err)
			}
			for _, f := range out {
				utils.Indent(log.Info, 2)("Created " + f)
			}
		}

		return nil
	},
}
