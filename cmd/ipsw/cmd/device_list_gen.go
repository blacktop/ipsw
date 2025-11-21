//go:build darwin && cgo

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
package cmd

import (
	"encoding/json"
	"os"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/xcode"
	"github.com/spf13/cobra"
)

// deviceListGenCmd represents the deviceListGen command
var deviceListGenCmd = &cobra.Command{
	Use:   "device-list-gen",
	Short: "Generate iOS devices database (additive - merges with existing data)",
	Long: `Generate iOS devices database from Xcode's device_traits.db (additive - merges with existing data).

WARNING: Xcode's device database includes simulator devices and may not accurately
map to physical hardware devices. The data should be used as a reference and may
require manual verification for production use.`,
	Args:   cobra.MinimumNArgs(1),
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		log.Warn("Reading from Xcode device database (includes simulator devices, may not map to physical hardware)")

		// Read new devices from Xcode database
		newDevices, err := xcode.ReadDeviceTraitsDB()
		if err != nil {
			return err
		}
		log.Infof("Found %d devices in Xcode database", len(newDevices))

		// Try to read existing devices from target file
		var existingDevices []xcode.Device
		if data, err := os.ReadFile(args[0]); err == nil {
			if err := json.Unmarshal(data, &existingDevices); err != nil {
				log.Warnf("Failed to parse existing file, will overwrite: %v", err)
				existingDevices = nil
			} else {
				log.Infof("Loaded %d existing devices from %s", len(existingDevices), args[0])
			}
		} else {
			log.Info("No existing file found, creating new one")
		}

		// Merge existing devices with new ones
		allDevices := append(existingDevices, newDevices...)

		// Deduplicate by product_type + target (composite unique key)
		uniqueMap := make(map[string]xcode.Device)
		for _, device := range allDevices {
			if len(device.ProductType) != 0 && len(device.Target) != 0 {
				key := device.ProductType + "_" + device.Target
				// Later entries in the slice will overwrite earlier ones,
				// so new devices from Xcode will take precedence
				uniqueMap[key] = device
			}
		}

		// Convert back to slice
		mergedDevices := make([]xcode.Device, 0, len(uniqueMap))
		for _, device := range uniqueMap {
			mergedDevices = append(mergedDevices, device)
		}

		log.Infof("Writing %d total devices to %s", len(mergedDevices), args[0])

		err = xcode.WriteToJSON(mergedDevices, args[0])
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(deviceListGenCmd)
}
