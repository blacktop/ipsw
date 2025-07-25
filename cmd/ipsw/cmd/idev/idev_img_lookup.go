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
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/usb/mount"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	ImgCmd.AddCommand(idevImgLookupCmd)

	idevImgLookupCmd.Flags().BoolP("json", "j", false, "Display images as JSON")
	viper.BindPFlag("idev.img.lookup.json", idevImgLookupCmd.Flags().Lookup("json"))
}

// idevImgLookupCmd represents the lookup command
var idevImgLookupCmd = &cobra.Command{
	Use:           "lookup [Developer|Cryptex]",
	Short:         "Lookup image type",
	ValidArgs:     []string{"Developer", "Cryptex"},
	Args:          cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		udid := viper.GetString("idev.udid")
		asJSON := viper.GetBool("idev.img.lookup.json")

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

		image, err := cli.LookupImage(args[0])
		if err != nil {
			return fmt.Errorf("failed to lookup image: %w", err)
		}

		if asJSON {
			imgJSON, err := json.Marshal(image)
			if err != nil {
				return fmt.Errorf("failed to marshal image to JSON: %s", err)
			}
			fmt.Println(string(imgJSON))
		} else {
			fmt.Printf("Signature: %s\n", hex.EncodeToString(image.ImageSignature[0]))
		}

		return nil
	},
}
