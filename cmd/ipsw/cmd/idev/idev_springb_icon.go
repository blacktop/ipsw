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
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
	"github.com/blacktop/ipsw/pkg/usb/springboard"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	SpringbCmd.AddCommand(idevSpringbIconCmd)

	idevSpringbIconCmd.Flags().StringP("output", "o", "", "Folder to save icon")
	idevSpringbIconCmd.MarkFlagDirname("output")
	viper.BindPFlag("idev.springb.icon.output", idevSpringbIconCmd.Flags().Lookup("output"))
}

// idevSpringbIconCmd represents the icon command
var idevSpringbIconCmd = &cobra.Command{
	Use:           "icon",
	Short:         "Dump application icon as PNG",
	Args:          cobra.MinimumNArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		udid := viper.GetString("idev.udid")
		output := viper.GetString("idev.springb.icon.output")

		var err error
		var dev *lockdownd.DeviceValues
		if len(udid) == 0 {
			dev, err = utils.PickDevice()
			if err != nil {
				return fmt.Errorf("failed to pick USB connected devices: %w", err)
			}
		} else {
			ldc, err := lockdownd.NewClient(udid)
			if err != nil {
				return fmt.Errorf("failed to connect to lockdownd: %w", err)
			}
			dev, err = ldc.GetValues()
			if err != nil {
				return fmt.Errorf("failed to get device values for %s: %w", udid, err)
			}
			ldc.Close()
		}

		cli, err := springboard.NewClient(dev.UniqueDeviceID)
		if err != nil {
			return fmt.Errorf("failed to connect to springboard: %w", err)
		}
		defer cli.Close()

		iconData, err := cli.GetIcon(args[0])
		if err != nil {
			return fmt.Errorf("failed to get wallpaper: %w", err)
		}

		fname := filepath.Join(output, fmt.Sprintf("%s_%s_%s", dev.ProductType, dev.HardwareModel, dev.BuildVersion), fmt.Sprintf("%s_icon.png", args[0]))
		if err := os.MkdirAll(filepath.Dir(fname), 0755); err != nil {
			return fmt.Errorf("failed to create wallpaper directory %s: %w", filepath.Dir(fname), err)
		}
		log.Infof("Creating %s icon: %s", args[0], fname)
		return os.WriteFile(fname, iconData, 0660)
	},
}
