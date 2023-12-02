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
package idev

import (
	"encoding/json"
	"fmt"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/usb/diagnostics"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DiagCmd.AddCommand(diagBatCmd)
	diagBatCmd.Flags().BoolP("json", "j", false, "Display battery snapshot as JSON")
}

// diagBatCmd represents the bat command
var diagBatCmd = &cobra.Command{
	Use:           "bat",
	Short:         "Get snapshot of battery data",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		udid, _ := cmd.Flags().GetString("udid")
		asJSON, _ := cmd.Flags().GetBool("json")

		if len(udid) == 0 {
			dev, err := utils.PickDevice()
			if err != nil {
				return fmt.Errorf("failed to pick USB connected devices: %w", err)
			}
			udid = dev.UniqueDeviceID
		}

		cli, err := diagnostics.NewClient(udid)
		if err != nil {
			return fmt.Errorf("failed to connect to diagnostics: %w", err)
		}
		defer cli.Close()

		dinfo, err := cli.Battery()
		if err != nil {
			return fmt.Errorf("failed to query ioregistry for ioclass IOPMPowerSource: %w", err)
		}

		if asJSON {
			diJSON, err := json.Marshal(dinfo)
			if err != nil {
				return fmt.Errorf("failed to marshal diagnostics info response to JSON: %s", err)
			}
			fmt.Println(string(diJSON))
		} else {
			fmt.Println(dinfo)
		}

		return nil
	},
}
