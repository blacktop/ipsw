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
	"github.com/apex/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	FwCmd.AddCommand(dcpCmd)

	dcpCmd.Flags().StringP("output", "o", "", "Folder to extract files to")
	dcpCmd.MarkFlagDirname("output")
	viper.BindPFlag("fw.dcp.output", dcpCmd.Flags().Lookup("output"))
}

// dcpCmd represents the dcp command
var dcpCmd = &cobra.Command{
	Use:     "dcp",
	Aliases: []string{"d"},
	Short:   "🚧 Dump MachOs",
	Hidden:  true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		// Firmware/dcp/t8130dcp.im4p
		// Firmware/dcp/t8130dcp_restore.im4p

		// flags
		// output := viper.GetString("fw.dcp.output")

		panic("not implemented")

		return nil
	},
}
