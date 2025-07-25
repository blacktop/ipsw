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
package idev

import (
	"encoding/json"
	"fmt"

	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/usb/diagnostics"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DiagCmd.AddCommand(diagInfoCmd)
	diagInfoCmd.Flags().BoolP("json", "j", false, "Display diagnostics info as JSON")
	viper.BindPFlag("idev.diag.info.json", diagInfoCmd.Flags().Lookup("json"))
}

// diagInfoCmd represents the info command
var diagInfoCmd = &cobra.Command{
	Use:           "info",
	Short:         "Diagnostics info",
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		udid := viper.GetString("idev.udid")
		asJSON := viper.GetBool("idev.diag.info.json")

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

		dinfo, err := cli.Info()
		if err != nil {
			return fmt.Errorf("failed to query diagnostics info: %w", err)
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
