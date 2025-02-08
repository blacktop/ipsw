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

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/usb/mount"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	ImgCmd.AddCommand(idevImgUnmountCmd)

	idevImgUnmountCmd.Flags().StringP("image-type", "t", "", "Image type to unmount (i.e. 'Developer')")
	idevImgUnmountCmd.Flags().StringP("mount-point", "m", "", "Path to mount point (i.e. '/Developer')")
}

// idevImgUnmountCmd represents the unmount command
var idevImgUnmountCmd = &cobra.Command{
	Use:           "unmount",
	Short:         "Unmount an image",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		udid, _ := cmd.Flags().GetString("udid")
		imageType, _ := cmd.Flags().GetString("image-type")
		mountPoint, _ := cmd.Flags().GetString("mount-point")

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

		if imageType != "" && mountPoint != "" {
			log.Infof("Unmounting %s image from %s", imageType, mountPoint)
			if err := cli.Unmount(imageType, mountPoint, []byte{}); err != nil {
				return fmt.Errorf("failed to unmount image: %w", err)
			}
		} else {
			images, err := cli.ListImages()
			if err != nil {
				return fmt.Errorf("failed to list images: %w", err)
			}

			if len(images) == 0 {
				log.Warn("No mounted images found")
				return nil
			}

			if len(images) == 1 && images[0].IsMounted {
				log.Infof("Unmounting %s image from %s", images[0].DiskImageType, images[0].MountPath)
				if err := cli.Unmount(images[0].DiskImageType, images[0].MountPath, []byte(images[0].ImageSignature)); err != nil {
					return fmt.Errorf("failed to unmount image: %w", err)
				}
				return nil
			}

			for _, img := range images {
				log.Infof("Unmounting %s image from %s", img.DiskImageType, img.MountPath)
				if err := cli.Unmount(img.DiskImageType, img.MountPath, []byte(images[0].ImageSignature)); err != nil {
					return fmt.Errorf("failed to unmount image: %w", err)
				}
			}
		}

		return nil
	},
}
