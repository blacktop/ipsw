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
	"github.com/blacktop/ipsw/pkg/usb/mount"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	ImgCmd.AddCommand(idevImgListCmd)

	idevImgListCmd.Flags().BoolP("json", "j", false, "Display images as JSON")
	viper.BindPFlag("idev.img.ls.json", idevImgListCmd.Flags().Lookup("json"))
}

// idevImgListCmd represents the ls command
var idevImgListCmd = &cobra.Command{
	Use:           "ls",
	Short:         "List mounted images",
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		udid := viper.GetString("idev.udid")
		asJSON := viper.GetBool("idev.img.ls.json")

		if len(udid) == 0 {
			dev, err := utils.PickDevice()
			if err != nil {
				return fmt.Errorf("failed to pick USB connected devices: %w", err)
			}
			udid = dev.UniqueDeviceID
		}

		cli, err := mount.NewClient(udid)
		if err != nil {
			return fmt.Errorf("failed to connect to mobile_image_mounter: %w", err)
		}
		defer cli.Close()

		images, err := cli.ListImages()
		if err != nil {
			return fmt.Errorf("failed to list images: %w", err)
		}

		if len(images) == 0 {
			log.Warn("No images found")
			return nil
		}

		if asJSON {
			imgJSON, err := json.Marshal(images)
			if err != nil {
				return fmt.Errorf("failed to marshal images to JSON: %s", err)
			}
			fmt.Println(string(imgJSON))
		} else {
			for _, image := range images {
				fmt.Println("---")
				fmt.Println(image)
				fmt.Println()
			}
		}

		return nil
	},
}
