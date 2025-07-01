/*
Copyright © 2025 blacktop

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
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/commands/extract"
	fwcmd "github.com/blacktop/ipsw/internal/commands/fw"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// NOTE:
//   Firmware/image4/exclavecore_bundle.t8132.RELEASE.im4p

func init() {
	FwCmd.AddCommand(excCmd)

	excCmd.Flags().BoolP("remote", "r", false, "Parse remote IPSW URL")
	excCmd.Flags().BoolP("info", "i", false, "Print info")
	excCmd.Flags().StringP("output", "o", "", "Folder to extract files to")
	excCmd.MarkFlagDirname("output")
	viper.BindPFlag("fw.exclave.remote", excCmd.Flags().Lookup("remote"))
	viper.BindPFlag("fw.exclave.info", excCmd.Flags().Lookup("info"))
	viper.BindPFlag("fw.exclave.output", excCmd.Flags().Lookup("output"))
}

// excCmd represents the ane command
var excCmd = &cobra.Command{
	Use:           "exclave <IPSW|URL|IM4P|BUNDLE>",
	Aliases:       []string{"exc"},
	Short:         "Dump MachOs",
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) (err error) {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		showInfo := viper.GetBool("fw.exclave.info")
		output := viper.GetString("fw.exclave.output")

		infile := filepath.Clean(args[0])

		if isZip, err := magic.IsZip(infile); err != nil && !viper.GetBool("fw.exclave.remote") {
			return fmt.Errorf("failed to determine if file is a zip: %v", err)
		} else if isZip || viper.GetBool("fw.exclave.remote") {
			var out []string
			if viper.GetBool("fw.exclave.remote") {
				out, err = extract.Exclave(&extract.Config{
					URL:    args[0],
					Info:   showInfo,
					Output: output,
				})
				if err != nil {
					return fmt.Errorf("failed to extract files from exclave bundle from remote IPSW: %v", err)
				}
			} else {
				out, err = extract.Exclave(&extract.Config{
					IPSW:   infile,
					Info:   showInfo,
					Output: output,
				})
				if err != nil {
					return fmt.Errorf("failed to extract files from exclave bundle from local IPSW: %v", err)
				}
			}
			for _, f := range out {
				utils.Indent(log.Info, 2)("Created " + f)
			}
		} else if ok, _ := magic.IsIm4p(infile); ok {
			im4p, err := img4.OpenPayload(infile)
			if err != nil {
				return err
			}
			data, err := im4p.GetData()
			if err != nil {
				return fmt.Errorf("failed to get data from exclave img4 payload: %v", err)
			}
			if showInfo {
				fwcmd.ShowExclaveCores(data)
				return nil
			}
			log.Info("Extracting Exclave Bundle")
			out, err := fwcmd.ExtractExclaveCores(data, output)
			if err != nil {
				return fmt.Errorf("failed to extract files from exclave bundle: %v", err)
			}
			for _, f := range out {
				utils.Indent(log.Info, 2)("Created " + f)
			}
		} else {
			data, err := os.ReadFile(infile)
			if err != nil {
				return fmt.Errorf("failed to read file %s: %v", infile, err)
			}
			if showInfo {
				fwcmd.ShowExclaveCores(data)
				return nil
			}
			log.Info("Extracting Exclave Bundle")
			out, err := fwcmd.ExtractExclaveCores(data, output)
			if err != nil {
				return fmt.Errorf("failed to extract files from exclave bundle: %v", err)
			}
			for _, f := range out {
				utils.Indent(log.Info, 2)("Created " + f)
			}
		}

		return nil
	},
}
