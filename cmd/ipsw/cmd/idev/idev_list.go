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
	"github.com/blacktop/ipsw/pkg/usb"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	IDevCmd.AddCommand(ListDevicesCmd)

	ListDevicesCmd.Flags().BoolP("ipsw", "i", false, "Display devices as ipsw spec names")
	ListDevicesCmd.Flags().BoolP("json", "j", false, "Display devices as JSON")
	viper.BindPFlag("idev.list.ipsw", ListDevicesCmd.Flags().Lookup("ipsw"))
	viper.BindPFlag("idev.list.json", ListDevicesCmd.Flags().Lookup("json"))
}

// listCmd represents the list command
var ListDevicesCmd = &cobra.Command{
	Use:           "list",
	Short:         "Dump info about USB connected iDevices",
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		ipswSpec := viper.GetBool("idev.list.ipsw")
		asJSON := viper.GetBool("idev.list.json")

		conn, err := usb.NewConn()
		if err != nil {
			return fmt.Errorf("failed to connect to usbmuxd: %w", err)
		}
		defer conn.Close()

		devices, err := conn.ListDevices()
		if err != nil {
			return err
		}

		if len(devices) == 0 {
			log.Warn("no devices found")
			return nil
		}

		var dds []*lockdownd.DeviceValues

		for _, device := range devices {
			cli, err := lockdownd.NewClient(device.SerialNumber)
			if err != nil {
				return err
			}

			values, err := cli.GetValues()
			if err != nil {
				return err
			}

			if ipswSpec {
				fmt.Printf("%s_%s_%s\n", values.ProductType, values.HardwareModel, values.BuildVersion)
			} else if asJSON {
				dds = append(dds, values)
			} else {
				fmt.Println(device)
				fmt.Println(values)
			}

			cli.Close()
		}

		if asJSON {
			ddsJSON, err := json.Marshal(dds)
			if err != nil {
				return fmt.Errorf("failed to marshal device details to JSON: %s", err)
			}
			fmt.Println(string(ddsJSON))
		}

		return nil
	},
}
