/*
Copyright © 2022 blacktop

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
package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/usb"
	"github.com/blacktop/ipsw/pkg/usb/lockdown"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(idevCmd)
	idevCmd.Flags().BoolP("ipsw", "i", false, "Display devices as ipsw spec names")
	idevCmd.Flags().BoolP("json", "j", false, "Display devices as JSON")
}

// idevCmd represents the idev command
var idevCmd = &cobra.Command{
	Use:           "idev",
	Short:         "Dump info about USB connected iDevices",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		ipswSpec, _ := cmd.Flags().GetBool("ipsw")
		asJSON, _ := cmd.Flags().GetBool("json")

		uconn, err := usb.NewConnection(AppVersion)
		if err != nil {
			return err
		}
		defer uconn.Close()

		devs, err := uconn.ListDevices()
		if err != nil {
			return err
		}

		var dds []*lockdown.DeviceDetail
		for _, dev := range devs {

			ld, err := uconn.ConnectLockdown(dev)
			if err != nil {
				return err
			}

			if err := ld.StartSession(); err != nil {
				return err
			}

			// if _, err := ld.StartService("com.apple.instruments.remoteserver"); err != nil {
			// 	return err
			// }

			dd, err := ld.GetDeviceDetail(dev)
			if err != nil {
				return err
			}

			if ipswSpec {
				fmt.Printf("%s_%s_%s\n", dd.ProductType, dd.HardwareModel, dd.BuildVersion)
			} else if asJSON {
				dds = append(dds, dd)
			} else {
				fmt.Println(dev)
				fmt.Printf(
					"Device Name:         %s\n"+
						"Device Color:        %s\n"+
						"Device Class:        %s\n"+
						"Product Name:        %s\n"+
						"Product Type:        %s\n"+
						"HardwareModel:       %s\n"+
						"BoardId:             %d\n"+
						"BuildVersion:        %s\n"+
						"Product Version:     %s\n"+
						"ChipID:              %#x (%s)\n"+
						"ProductionSOC:       %t\n"+
						"HasSiDP:             %t\n"+
						"TelephonyCapability: %t\n"+
						"UniqueChipID:        %#x\n"+
						"DieID:               %#x\n"+
						"PartitionType:       %s\n"+
						"UniqueDeviceID:      %s\n"+
						"WiFiAddress:         %s\n\n",
					dd.DeviceName,
					dd.DeviceColor,
					dd.DeviceClass,
					dd.ProductName,
					dd.ProductType,
					dd.HardwareModel,
					dd.BoardId,
					dd.BuildVersion,
					dd.ProductVersion,
					dd.ChipID,
					dd.CPUArchitecture,
					dd.ProductionSOC,
					dd.HasSiDP,
					dd.TelephonyCapability,
					dd.UniqueChipID,
					dd.DieID,
					dd.PartitionType,
					dd.UniqueDeviceID,
					dd.WiFiAddress,
				)
			}

			if err := ld.StopSession(); err != nil {
				return err
			}
			if err := uconn.Refresh(); err != nil {
				return err
			}
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
