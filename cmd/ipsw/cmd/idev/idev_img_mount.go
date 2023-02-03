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
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
	"github.com/blacktop/ipsw/pkg/usb/mount"
	semver "github.com/hashicorp/go-version"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	ImgCmd.AddCommand(idevImgMountCmd)

	idevImgMountCmd.Flags().StringP("xcode", "x", "/Applications/Xcode.app", "Path to Xcode.app")
	idevImgMountCmd.Flags().StringP("image-type", "t", "Developer", "Image type to mount")
	idevImgMountCmd.Flags().StringP("trust-cache", "c", "", "Cryptex trust cache to use")
	idevImgMountCmd.Flags().StringP("info-plist", "i", "", "Cryptex Info.plist to use")

	viper.BindPFlag("idev.img.mount.xcode", idevImgMountCmd.Flags().Lookup("xcode"))
	viper.BindPFlag("idev.img.mount.image-type", idevImgMountCmd.Flags().Lookup("image-type"))
	viper.BindPFlag("idev.img.mount.trust-cache", idevImgMountCmd.Flags().Lookup("trust-cache"))
	viper.BindPFlag("idev.img.mount.info-plist", idevImgMountCmd.Flags().Lookup("info-plist"))
}

// idevImgMountCmd represents the mount command
var idevImgMountCmd = &cobra.Command{
	Use:           "mount <image> <signature>",
	Short:         "Mount an image",
	Args:          cobra.MaximumNArgs(2),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		udid, _ := cmd.Flags().GetString("udid")
		xcode := viper.GetString("idev.img.mount.xcode")
		imageType := viper.GetString("idev.img.mount.image-type")
		trustCache := viper.GetString("idev.img.mount.trust-cache")
		infoPlist := viper.GetString("idev.img.mount.info-plist")

		if !utils.StrSliceContains([]string{"Developer", "Cryptex"}, imageType) {
			return fmt.Errorf("invalid --image-type: %s (must be Developer or Cryptex)", imageType)
		}
		if imageType == "Developer" && (len(trustCache) > 0 || len(infoPlist) > 0) {
			return fmt.Errorf("invalid flags --trust-cache or --info-plist (not allowed when --image-type=Developer)")
		}

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

		cli, err := mount.NewClient(dev.UniqueDeviceID)
		if err != nil {
			return fmt.Errorf("failed to connect to mobile_image_mounter: %w", err)
		}
		defer cli.Close()

		if _, err := cli.LookupImage(imageType); err == nil {
			log.Warnf("image type %s already mounted", imageType)
			return nil
		}

		var imgData []byte
		var sigData []byte

		if len(args) == 0 {
			version, err := semver.NewVersion(dev.ProductVersion)
			if err != nil {
				log.Fatal("failed to convert version into semver object")
			}
			imgData, err = os.ReadFile(
				filepath.Join(xcode,
					fmt.Sprintf("/Contents/Developer/Platforms/iPhoneOS.platform/DeviceSupport/%d.%d/DeveloperDiskImage.dmg",
						version.Segments()[0],
						version.Segments()[1],
					)))
			if err != nil {
				return fmt.Errorf("failed to read DeveloperDiskImage.dmg: %w", err)
			}
			sigData, err = os.ReadFile(
				filepath.Join(xcode,
					fmt.Sprintf("/Contents/Developer/Platforms/iPhoneOS.platform/DeviceSupport/%d.%d/DeveloperDiskImage.dmg.signature",
						version.Segments()[0],
						version.Segments()[1],
					)))
			if err != nil {
				return fmt.Errorf("failed to read DeveloperDiskImage.dmg.signature: %w", err)
			}
		} else {
			imgData, err = os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("failed to read image: %w", err)
			}
			sigData, err = os.ReadFile(args[1])
			if err != nil {
				return fmt.Errorf("failed to read image: %w", err)
			}
		}

		log.Infof("Uploading %s image", imageType)
		if err := cli.Upload(imageType, imgData, sigData); err != nil {
			return fmt.Errorf("failed to upload image: %w", err)
		}
		log.Infof("Mounting %s image", imageType)
		if err := cli.Mount(imageType, sigData, trustCache, infoPlist); err != nil {
			return fmt.Errorf("failed to mount image: %w", err)
		}

		return nil
	},
}
