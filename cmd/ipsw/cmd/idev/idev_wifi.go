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
	"fmt"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	IDevCmd.AddCommand(wifiCmd)

	wifiCmd.Flags().Bool("on", false, "Turn WiFi on")
	wifiCmd.Flags().Bool("off", false, "Turn WiFi off")
}

// wifiCmd represents the wifi command
var wifiCmd = &cobra.Command{
	Use:           "wifi",
	Short:         "Get/Set wifi connections state",
	SilenceUsage:  true,
	SilenceErrors: true,
	Args:          cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		udid, _ := cmd.Flags().GetString("udid")
		turnON, _ := cmd.Flags().GetBool("on")
		turnOFF, _ := cmd.Flags().GetBool("off")

		if len(udid) == 0 {
			dev, err := utils.PickDevice()
			if err != nil {
				return fmt.Errorf("failed to pick USB connected devices: %w", err)
			}
			udid = dev.UniqueDeviceID
		}

		cli, err := lockdownd.NewClient(udid)
		if err != nil {
			return fmt.Errorf("failed to create lockdownd client: %w", err)
		}
		defer cli.Close()

		if turnON || turnOFF {
			if err := cli.SetWifiConnections(turnON); err != nil {
				return fmt.Errorf("failed to set wifi connections: %w", err)
			}
		}

		wifi, err := cli.WifiConnections()
		if err != nil {
			return fmt.Errorf("failed to get wifi connections: %w", err)
		}

		fmt.Println(wifi)

		return nil
	},
}
