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
	"crypto/sha512"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/plist"
	"github.com/blacktop/ipsw/pkg/tss"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
	"github.com/blacktop/ipsw/pkg/usb/mount"
	"github.com/fatih/color"
	semver "github.com/hashicorp/go-version"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	ImgCmd.AddCommand(idevImgMountCmd)

	idevImgMountCmd.Flags().StringP("xcode", "x", "", "Path to Xcode.app (i.e. /Applications/Xcode.app)")
	idevImgMountCmd.Flags().StringP("ddi-img", "d", "", "DDI.dmg to mount")
	idevImgMountCmd.Flags().StringP("trustcache", "c", "", "trustcache to use")
	idevImgMountCmd.Flags().StringP("manifest", "m", "", "BuildManifest.plist to use")
	idevImgMountCmd.Flags().StringP("signature", "s", "", "Image signature to use")
	idevImgMountCmd.Flags().StringP("image-type", "t", "", "Image type to mount (i.e. Developer)")
	idevImgMountCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	idevImgMountCmd.Flags().Bool("insecure", false, "do not verify ssl certs")

	viper.BindPFlag("idev.img.mount.xcode", idevImgMountCmd.Flags().Lookup("xcode"))
	viper.BindPFlag("idev.img.mount.ddi-img", idevImgMountCmd.Flags().Lookup("ddi-img"))
	viper.BindPFlag("idev.img.mount.trustcache", idevImgMountCmd.Flags().Lookup("trustcache"))
	viper.BindPFlag("idev.img.mount.manifest", idevImgMountCmd.Flags().Lookup("manifest"))
	viper.BindPFlag("idev.img.mount.signature", idevImgMountCmd.Flags().Lookup("signature"))
	viper.BindPFlag("idev.img.mount.image-type", idevImgMountCmd.Flags().Lookup("image-type"))
	viper.BindPFlag("idev.img.mount.proxy", idevImgMountCmd.Flags().Lookup("proxy"))
	viper.BindPFlag("idev.img.mount.insecure", idevImgMountCmd.Flags().Lookup("insecure"))
}

// idevImgMountCmd represents the mount command
var idevImgMountCmd = &cobra.Command{
	Use:           "mount",
	Short:         "Mount an image",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")
		// flags
		udid, _ := cmd.Flags().GetString("udid")
		xcode := viper.GetString("idev.img.mount.xcode")
		dmgPath := viper.GetString("idev.img.mount.ddi-img")
		trustcachePath := viper.GetString("idev.img.mount.trustcache")
		manifestPath := viper.GetString("idev.img.mount.manifest")
		signaturePath := viper.GetString("idev.img.mount.signature")
		imageType := viper.GetString("idev.img.mount.image-type")
		// verify flags
		if xcode != "" && (dmgPath != "" || trustcachePath != "" || manifestPath != "") {
			return fmt.Errorf("cannot specify both --xcode AND ('--ddi-img' OR '--trust-cache' OR '--manifest')")
		} else if xcode == "" && (dmgPath == "" && trustcachePath == "" && manifestPath == "") {
			return fmt.Errorf("must specify either --xcode OR ('--ddi-img' AND '--trustcache' AND '--manifest')")
		}
		if !utils.StrSliceContains([]string{"Developer", "Cryptex", "Personalized"}, imageType) {
			return fmt.Errorf("invalid --image-type: %s (must be Developer, Cryptex or Personalized)", imageType)
		}
		if imageType == "Developer" && (len(trustcachePath) > 0 || len(manifestPath) > 0) {
			return fmt.Errorf("invalid flags --trustcache or --manifest (not allowed when --image-type=Developer)")
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

		ver, err := semver.NewVersion(dev.ProductVersion) // check
		if err != nil {
			return fmt.Errorf("failed to convert version into semver object")
		}

		if ver.LessThan(semver.Must(semver.NewVersion("17.0"))) {
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
				imgData, err = os.ReadFile(dmgPath)
				if err != nil {
					return fmt.Errorf("failed to read image '%s': %w", dmgPath, err)
				}
				sigData, err = os.ReadFile(signaturePath)
				if err != nil {
					return fmt.Errorf("failed to read signature '%s': %w", signaturePath, err)
				}
			}

			log.Infof("Uploading %s image", imageType)
			if err := cli.Upload(imageType, imgData, sigData); err != nil {
				return fmt.Errorf("failed to upload image: %w", err)
			}
			log.Infof("Mounting %s image", imageType)
			if err := cli.Mount(imageType, sigData, trustcachePath, manifestPath); err != nil {
				return fmt.Errorf("failed to mount image: %w", err)
			}
		} else { // NEW iOS17 DDIs need to be personalized
			var buildManifest *plist.BuildManifest

			imageType = "Personalized"

			if len(dmgPath) == 0 {
				ddiDMG := filepath.Join(xcode, "/Contents/Resources/CoreDeviceDDIs/iOS_DDI.dmg")
				if _, err := os.Stat(ddiDMG); errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("failed to find iOS_DDI.dmg in '%s' (install NEW XCode.app or Xcode-beta.app)", xcode)
				}
				utils.Indent(log.Info, 2)(fmt.Sprintf("Mounting %s", ddiDMG))
				mountPoint, alreadyMounted, err := utils.MountDMG(ddiDMG)
				if err != nil {
					return fmt.Errorf("failed to mount iOS_DDI.dmg: %w", err)
				}
				if alreadyMounted {
					utils.Indent(log.Info, 3)(fmt.Sprintf("%s already mounted", ddiDMG))
				} else {
					defer func() {
						utils.Indent(log.Debug, 2)(fmt.Sprintf("Unmounting %s", ddiDMG))
						if err := utils.Retry(3, 2*time.Second, func() error {
							return utils.Unmount(mountPoint, false)
						}); err != nil {
							log.Errorf("failed to unmount %s at %s: %v", ddiDMG, mountPoint, err)
						}
					}()
				}
				manifestPath := filepath.Join(mountPoint, "Restore/BuildManifest.plist")
				manifestData, err := os.ReadFile(manifestPath)
				if err != nil {
					return fmt.Errorf("failed to read BuildManifest.plist: %w", err)
				}
				buildManifest, err = plist.ParseBuildManifest(manifestData)
				if err != nil {
					return fmt.Errorf("failed to parse BuildManifest.plist: %w", err)
				}
				trustcachePath = filepath.Join(mountPoint, "Restore", buildManifest.BuildIdentities[0].Manifest["LoadableTrustCache"].Info["Path"].(string))
				dmgPath = filepath.Join(mountPoint, "Restore", buildManifest.BuildIdentities[0].Manifest["PersonalizedDMG"].Info["Path"].(string))
			}

			if len(manifestPath) > 0 {
				manifestData, err := os.ReadFile(manifestPath)
				if err != nil {
					return fmt.Errorf("failed to read BuildManifest.plist: %w", err)
				}
				buildManifest, err = plist.ParseBuildManifest(manifestData)
				if err != nil {
					return fmt.Errorf("failed to parse BuildManifest.plist: %w", err)
				}
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

			imgData, err := os.ReadFile(dmgPath)
			if err != nil {
				return fmt.Errorf("failed to read PersonalizedDMG: %w", err)
			}

			var sigData []byte
			if len(signaturePath) > 0 {
				sigData, err = os.ReadFile(signaturePath)
				if err != nil {
					return fmt.Errorf("failed to read signature '%s': %w", signaturePath, err)
				}
			} else {
				digest := sha512.Sum384(imgData)
				sigData, err = cli.PersonalizationManifest("DeveloperDiskImage", digest[:])
				if err != nil {
					log.Debugf("failed to get personalization manifest: %w", err)

					nonce, err := cli.Nonce("DeveloperDiskImage")
					if err != nil {
						return fmt.Errorf("failed to get nonce: %w", err)
					}

					personalID, err := cli.PersonalizationIdentifiers("")
					if err != nil {
						log.Errorf("failed to get personalization identifiers: %v ('personalization' might not be supported on this device)", err)
					}

					personalID["ApNonce"] = nonce

					sigData, err = tss.Personalize(&tss.PersonalConfig{
						Proxy:         viper.GetString("idev.img.mount.proxy"),
						Insecure:      viper.GetBool("idev.img.mount.insecure"),
						PersonlID:     personalID,
						BuildManifest: buildManifest,
					})
				}
			}

			log.Infof("Uploading %s image", imageType)
			if err := cli.Upload(imageType, imgData, sigData); err != nil {
				return fmt.Errorf("failed to upload image: %w", err)
			}
			log.Infof("Mounting %s image", imageType)
			if err := cli.Mount(imageType, sigData, trustcachePath, manifestPath); err != nil {
				return fmt.Errorf("failed to mount image: %w", err)
			}
		}

		return nil
	},
}
