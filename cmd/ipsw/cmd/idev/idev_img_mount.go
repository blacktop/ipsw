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
	"crypto/sha512"
	"fmt"
	"slices"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/commands/device"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/tss"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
	"github.com/blacktop/ipsw/pkg/usb/mount"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	ImgCmd.AddCommand(idevImgMountCmd)

	idevImgMountCmd.Flags().StringP("image-type", "t", "", "Image type to mount (i.e. Developer)")
	idevImgMountCmd.Flags().StringP("xcode", "x", "", "Path to Xcode.app (i.e. /Applications/Xcode.app)")
	idevImgMountCmd.Flags().StringP("ddi-img", "d", "", "DDI.dmg to mount")
	idevImgMountCmd.Flags().StringP("trustcache", "c", "", "trustcache to use")
	idevImgMountCmd.Flags().StringP("manifest", "m", "", "BuildManifest.plist to use")
	idevImgMountCmd.Flags().StringP("signature", "s", "", "Image signature to use")
	idevImgMountCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	idevImgMountCmd.Flags().Bool("insecure", false, "do not verify ssl certs")

	viper.BindPFlag("idev.img.mount.image-type", idevImgMountCmd.Flags().Lookup("image-type"))
	viper.BindPFlag("idev.img.mount.xcode", idevImgMountCmd.Flags().Lookup("xcode"))
	viper.BindPFlag("idev.img.mount.ddi-img", idevImgMountCmd.Flags().Lookup("ddi-img"))
	viper.BindPFlag("idev.img.mount.trustcache", idevImgMountCmd.Flags().Lookup("trustcache"))
	viper.BindPFlag("idev.img.mount.manifest", idevImgMountCmd.Flags().Lookup("manifest"))
	viper.BindPFlag("idev.img.mount.signature", idevImgMountCmd.Flags().Lookup("signature"))
	viper.BindPFlag("idev.img.mount.proxy", idevImgMountCmd.Flags().Lookup("proxy"))
	viper.BindPFlag("idev.img.mount.insecure", idevImgMountCmd.Flags().Lookup("insecure"))
}

// idevImgMountCmd represents the img mount command
var idevImgMountCmd = &cobra.Command{
	Use:           "mount",
	Short:         "Mount an image",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) (err error) {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// flags
		udid := viper.GetString("idev.udid")
		imageType := viper.GetString("idev.img.mount.image-type")
		xcodePath := viper.GetString("idev.img.mount.xcode")
		dmgPath := viper.GetString("idev.img.mount.ddi-img")
		signaturePath := viper.GetString("idev.img.mount.signature")
		trustcachePath := viper.GetString("idev.img.mount.trustcache")
		manifestPath := viper.GetString("idev.img.mount.manifest")

		// verify flags
		if !slices.Contains([]string{"Developer", "Cryptex", "Personalized"}, imageType) {
			return fmt.Errorf("invalid --image-type: %s (must be Developer, Cryptex or Personalized)", imageType)
		}
		if imageType == "Developer" && (len(trustcachePath) > 0 || len(manifestPath) > 0) {
			return fmt.Errorf("invalid flags --trustcache or --manifest (not allowed when --image-type=Developer)")
		}
		if xcodePath != "" && (dmgPath != "" || trustcachePath != "" || manifestPath != "") {
			return fmt.Errorf("cannot specify both --xcode AND ('--ddi-img' OR '--trust-cache' OR '--manifest')")
		}

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

		// Get DDI configuration using the new function from internal package
		ddi, err := device.GetDDIInfo(&device.DDIConfig{
			Dev:            dev,
			ImageType:      imageType,
			XCodePath:      xcodePath,
			DDIFile:        dmgPath,
			SigFile:        signaturePath,
			TrustcachePath: trustcachePath,
			ManifestPath:   manifestPath,
		})
		if err != nil {
			return fmt.Errorf("failed to get DDI configuration: %w", err)
		}
		defer ddi.Clean()

		// Handle personalization for iOS 17+ with missing signature
		if ddi.BuildManifest != nil && len(ddi.SignatureData) == 0 {
			digest := sha512.Sum384(ddi.ImageData)
			ddi.SignatureData, err = cli.PersonalizationManifest("DeveloperDiskImage", digest[:])
			if err != nil {
				log.Debugf("failed to get personalization manifest: %v", err)

				nonce, err := cli.Nonce("DeveloperDiskImage")
				if err != nil {
					return fmt.Errorf("failed to get nonce: %w", err)
				}

				personalID, err := cli.PersonalizationIdentifiers("")
				if err != nil {
					return fmt.Errorf("failed to get personalization identifiers ('personalization' might not be supported on this device): %w", err)
				}
				personalID["ApNonce"] = nonce

				ddi.SignatureData, err = tss.Personalize(&tss.PersonalConfig{
					PersonlID:     personalID,
					BuildManifest: ddi.BuildManifest,
					Proxy:         viper.GetString("idev.img.mount.proxy"),
					Insecure:      viper.GetBool("idev.img.mount.insecure"),
				})
				if err != nil {
					return fmt.Errorf("failed to personalize DDI: %w", err)
				}
			}
		}

		log.WithField("type", imageType).Info("Uploading image")
		if err := cli.Upload(imageType, ddi.ImageData, ddi.SignatureData); err != nil {
			return fmt.Errorf("failed to upload image: %w", err)
		}
		log.WithField("type", imageType).Info("Mounting image")
		if err := cli.Mount(imageType, ddi.SignatureData, ddi.TrustcachePath, ddi.ManifestPath); err != nil {
			return fmt.Errorf("failed to mount image: %w", err)
		}

		return nil
	},
}
