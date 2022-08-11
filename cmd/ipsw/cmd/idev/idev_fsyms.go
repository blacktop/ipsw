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
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/usb/fetchsymbols"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	IDevCmd.AddCommand(FetchsymsCmd)

	FetchsymsCmd.Flags().StringP("output", "o", "", "Folder to save files")
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
			defer ldc.Close()

			dev, err = ldc.GetValues()
			if err != nil {
				return fmt.Errorf("failed to get device values for %s: %w", udid, err)
			}
		}

		cli := fetchsymbols.NewClient(dev.UniqueDeviceID)
		files, err := cli.ListFiles()
		if err != nil {
			return fmt.Errorf("failed to list files: %w", err)
		}

		for idx, file := range files {
			fname := filepath.Join(output, fmt.Sprintf("%s_%s_%s", dev.ProductType, dev.HardwareModel, dev.BuildVersion), file)
			if err := os.MkdirAll(filepath.Dir(fname), 0755); err != nil {
				return fmt.Errorf("failed to create fetchsymbols directory %s: %w", filepath.Dir(fname), err)
			}

			log.Infof("Copying %s", fname)
			fr, err := cli.GetFile(uint32(idx))
			if err != nil {
				return fmt.Errorf("failed to get file %s from device: %w", file, err)
			}

			var buf bytes.Buffer
			if _, err := buf.ReadFrom(fr); err != nil {
				return fmt.Errorf("failed to read file %s: %w", file, err)
			}

			if err := ioutil.WriteFile(fname, buf.Bytes(), 0660); err != nil {
				return fmt.Errorf("failed to write file %s: %w", fname, err)
			}
		}

		return nil
	},
}
