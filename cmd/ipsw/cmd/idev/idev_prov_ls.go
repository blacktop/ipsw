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
	"github.com/blacktop/ipsw/pkg/usb/misagent"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	ProvCmd.AddCommand(provLsCmd)

	provLsCmd.Flags().BoolP("json", "j", false, "Display profiles as JSON")
	viper.BindPFlag("idev.prov.ls.json", provLsCmd.Flags().Lookup("json"))
}

// provLsCmd represents the ls command
var provLsCmd = &cobra.Command{
	Use:           "ls",
	Short:         "List installed provisioning profiles",
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		udid := viper.GetString("idev.udid")
		asJSON := viper.GetBool("idev.prov.ls.json")

		if len(udid) == 0 {
			dev, err := utils.PickDevice()
			if err != nil {
				return fmt.Errorf("failed to pick USB connected devices: %w", err)
			}
			udid = dev.UniqueDeviceID
		}

		ms, err := misagent.NewClient(udid)
		if err != nil {
			return fmt.Errorf("failed to create misagent client: %w", err)
		}

		profs, err := ms.List()
		if err != nil {
			return fmt.Errorf("failed to list provision profiles: %w", err)
		}

		if asJSON {
			profsJSON, err := json.Marshal(profs)
			if err != nil {
				return fmt.Errorf("failed to marshal profiles details to JSON: %s", err)
			}
			fmt.Println(string(profsJSON))
		} else {
			for _, prof := range profs {
				fmt.Println(prof)
			}
		}

		return nil
	},
}
