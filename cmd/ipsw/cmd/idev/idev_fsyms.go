/*
Copyright © 2018-2024 blacktop

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
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/usb/fetchsymbols"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	IDevCmd.AddCommand(FetchsymsCmd)

	FetchsymsCmd.Flags().StringP("output", "o", "", "Folder to save files")
	FetchsymsCmd.MarkFlagDirname("output")
}

// FetchsymsCmd represents the fetchsyms command
var FetchsymsCmd = &cobra.Command{
	Use:           "fsyms",
	Short:         "Dump device linker and dyld_shared_cache file",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		udid, _ := cmd.Flags().GetString("udid")
		output, _ := cmd.Flags().GetString("output")

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

		if ok, err := utils.IsDeveloperModeEnabled(dev.UniqueDeviceID); !ok && err == nil {
			return fmt.Errorf("you must enable Developer Mode in your device Settings app for %s", dev.DeviceName)
		} else if err != nil {
			return fmt.Errorf("failed to check if developer mode is enabled for device %s: %w", dev.UniqueDeviceID, err)
		}
		if err := utils.IsDeveloperImageMounted(dev.UniqueDeviceID); err != nil {
			return fmt.Errorf("for device %s: %w", dev.UniqueDeviceID, err)
		}

		cli, err := fetchsymbols.NewClient(dev.UniqueDeviceID)
		if err != nil {
			return fmt.Errorf("failed to connect to fetchsymbols service: %w", err)
		}

		files, err := cli.ListFiles()
		if err != nil {
			return fmt.Errorf("failed to list files: %w", err)
		}
		cli.Close()

		for idx, file := range files {
			fname := filepath.Join(output, fmt.Sprintf("%s_%s_%s", dev.ProductType, dev.HardwareModel, dev.BuildVersion), file)
			if err := os.MkdirAll(filepath.Dir(fname), 0755); err != nil {
				return fmt.Errorf("failed to create fetchsymbols directory %s: %w", filepath.Dir(fname), err)
			}

			log.Infof("Copying %s", fname)
			cli, err := fetchsymbols.NewClient(dev.UniqueDeviceID)
			if err != nil {
				return fmt.Errorf("failed to connect to fetchsymbols service: %w", err)
			}
			fr, err := cli.GetFile(uint32(idx))
			if err != nil {
				return fmt.Errorf("failed to get file %s from device: %w", file, err)
			}

			var buf bytes.Buffer
			if _, err := buf.ReadFrom(fr); err != nil {
				return fmt.Errorf("failed to read file %s: %w", file, err)
			}

			if err := os.WriteFile(fname, buf.Bytes(), 0660); err != nil {
				return fmt.Errorf("failed to write file %s: %w", fname, err)
			}
			cli.Close()
		}

		return nil
	},
}
