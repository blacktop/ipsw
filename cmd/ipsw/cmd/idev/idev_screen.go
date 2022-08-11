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
package idev

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
	"github.com/blacktop/ipsw/pkg/usb/screenshot"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	IDevCmd.AddCommand(ScreenCmd)

	ScreenCmd.Flags().StringP("output", "o", "", "Folder to save screenshot(s)")
}

func saveScreenshot(dev *lockdownd.DeviceValues, destPath string) error {
	cli, err := screenshot.NewClient(dev.UniqueDeviceID)
	if err != nil {
		return fmt.Errorf("failed to connect to iDevice with UUID %s: %w", dev.UniqueDeviceID, err)
	}
	defer cli.Close()

	png, err := cli.Screenshot()
	if err != nil {
		return fmt.Errorf("failed to get screenshot: %w", err)
	}

	fname := fmt.Sprintf("screenshot_%s.png", time.Now().Format("02Jan2006_15:04:05MST"))
	fname = filepath.Join(destPath, fmt.Sprintf("%s_%s_%s", dev.ProductType, dev.HardwareModel, dev.BuildVersion), fname)
	if err := os.MkdirAll(filepath.Dir(fname), 0755); err != nil {
		return fmt.Errorf("failed to create screenshot directory %s: %w", filepath.Dir(fname), err)
	}
	log.Infof("Creating screenshot: %s", fname)
	return ioutil.WriteFile(fname, png, 0660)
}

// ScreenCmd represents the screen command
var ScreenCmd = &cobra.Command{
	Use:           "screen",
	Short:         "Dump screenshot as a PNG",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		udid, _ := cmd.Flags().GetString("udid")
		output, _ := cmd.Flags().GetString("output")

		if len(udid) > 0 {
			ldc, err := lockdownd.NewClient(udid)
			if err != nil {
				return err
			}
			defer ldc.Close()

			dev, err := ldc.GetValues()
			if err != nil {
				return err
			}
			return saveScreenshot(dev, output)
		} else {
			devs, err := utils.PickDevices()
			if err != nil {
				return fmt.Errorf("failed to pick USB connected devices: %w", err)
			}

			for _, dev := range devs {
				if err := saveScreenshot(dev, output); err != nil {
					return fmt.Errorf("failed to save screenshot: %w", err)
				}
			}
		}

		return nil
	},
}
