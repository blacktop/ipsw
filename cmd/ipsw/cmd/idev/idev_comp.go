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

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/usb/companion"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	IDevCmd.AddCommand(compCmd)
	compCmd.Flags().BoolP("json", "j", false, "Display companions as JSON")
	viper.BindPFlag("idev.comp.json", compCmd.Flags().Lookup("json"))
}

// compCmd represents the comp command
var compCmd = &cobra.Command{
	Use:           "comp",
	Short:         "List all paired companion devices",
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		udid := viper.GetString("idev.udid")
		asJSON := viper.GetBool("idev.comp.json")

		if len(udid) == 0 {
			dev, err := utils.PickDevice()
			if err != nil {
				return fmt.Errorf("failed to pick USB connected devices: %w", err)
			}
			udid = dev.UniqueDeviceID
		}

		cp, err := companion.NewClient(udid)
		if err != nil {
			return err
		}

		cmps, err := cp.List()
		if err != nil {
			return err
		}

		if asJSON {
			profsJSON, err := json.Marshal(cmps)
			if err != nil {
				return fmt.Errorf("failed to marshal companionsto JSON: %s", err)
			}
			fmt.Println(string(profsJSON))
		} else {
			log.Info("Paired Companion Devices:")
			for _, cmp := range cmps {
				fmt.Println(cmp)
			}
		}

		return nil
	},
}
