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
package fw

import (
	"fmt"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/commands/extract"
	fwcmd "github.com/blacktop/ipsw/internal/commands/fw"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/bundle"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// NOTE:
//   Firmware/image4/exclavecore_bundle.t8132.RELEASE.im4p

func init() {
	FwCmd.AddCommand(excCmd)

	excCmd.Flags().BoolP("info", "i", false, "Print info")
	excCmd.Flags().StringP("output", "o", "", "Folder to extract files to")
	excCmd.MarkFlagDirname("output")
	viper.BindPFlag("fw.exclave.info", excCmd.Flags().Lookup("info"))
	viper.BindPFlag("fw.exclave.output", excCmd.Flags().Lookup("output"))
}

// excCmd represents the ane command
var excCmd = &cobra.Command{
	Use:     "exclave",
	Aliases: []string{"exc"},
	Short:   "🚧 Dump MachOs",
	Args:    cobra.ExactArgs(1),
	Hidden:  true,
	RunE: func(cmd *cobra.Command, args []string) (err error) {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		showInfo := viper.GetBool("fw.exclave.info")
		output := viper.GetString("fw.exclave.output")

		if showInfo {
			bn, err := bundle.Parse(filepath.Clean(args[0]))
			if err != nil {
				return fmt.Errorf("failed to parse bundle: %v", err)
			}

			if bn.Type != 3 {
				return fmt.Errorf("bundle is not an exclave bundle")
			}

			fmt.Println(bn)
		} else {
			if isZip, err := magic.IsZip(filepath.Clean(args[0])); err != nil {
				return fmt.Errorf("failed to determine if file is a zip: %v", err)
			} else if isZip {
				out, err := extract.Exclave(&extract.Config{
					IPSW:   filepath.Clean(args[0]),
					Output: viper.GetString("fw.exclave.output"),
				})
				if err != nil {
					return err
				}
				for _, f := range out {
					utils.Indent(log.Info, 2)("Created " + f)
				}
			} else {
				log.Info("Extracting Exclave Bundle")
				out, err := fwcmd.Extract(filepath.Clean(args[0]), output)
				if err != nil {
					return fmt.Errorf("failed to extract files from exclave bundle: %v", err)
				}
				for _, f := range out {
					utils.Indent(log.Info, 2)("Created " + f)
				}
			}
		}

		return nil
	},
}
