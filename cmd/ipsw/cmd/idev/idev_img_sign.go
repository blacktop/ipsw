/*
Copyright © 2024 blacktop

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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/plist"
	"github.com/blacktop/ipsw/pkg/tss"
	"github.com/fatih/color"
	semver "github.com/hashicorp/go-version"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	ImgCmd.AddCommand(idevImgSignCmd)

	idevImgSignCmd.Flags().StringP("xcode", "x", "", "Path to Xcode.app")
	idevImgSignCmd.Flags().StringP("manifest", "m", "", "BuildManifest.plist to use")
	idevImgSignCmd.Flags().Uint64P("board-id", "b", 0, "Device ApBoardID")
	idevImgSignCmd.Flags().Uint64P("chip-id", "c", 0, "Device ApChipID")
	idevImgSignCmd.Flags().Uint64P("ecid", "e", 0, "Device ApECID")
	idevImgSignCmd.Flags().StringP("nonce", "n", "", "Device ApNonce")
	idevImgSignCmd.Flags().StringP("ap-item", "a", "", "Ap'Item to personalize (example: --ap-item 'Ap,SikaFuse')")
	idevImgSignCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	idevImgSignCmd.Flags().Bool("insecure", false, "do not verify ssl certs")
	idevImgSignCmd.Flags().StringP("input", "i", "", "JSON file from `ipsw idev img nonce --json` command")
	idevImgSignCmd.Flags().StringP("output", "o", "", "Folder to write signature to")
	idevImgSignCmd.MarkFlagDirname("output")

	viper.BindPFlag("idev.img.sign.xcode", idevImgSignCmd.Flags().Lookup("xcode"))
	viper.BindPFlag("idev.img.sign.manifest", idevImgSignCmd.Flags().Lookup("manifest"))
	viper.BindPFlag("idev.img.sign.board-id", idevImgSignCmd.Flags().Lookup("board-id"))
	viper.BindPFlag("idev.img.sign.chip-id", idevImgSignCmd.Flags().Lookup("chip-id"))
	viper.BindPFlag("idev.img.sign.ecid", idevImgSignCmd.Flags().Lookup("ecid"))
	viper.BindPFlag("idev.img.sign.ap-item", idevImgSignCmd.Flags().Lookup("ap-item"))
	viper.BindPFlag("idev.img.sign.nonce", idevImgSignCmd.Flags().Lookup("nonce"))
	viper.BindPFlag("idev.img.sign.input", idevImgSignCmd.Flags().Lookup("input"))
	viper.BindPFlag("idev.img.sign.output", idevImgSignCmd.Flags().Lookup("output"))
	viper.BindPFlag("idev.img.sign.proxy", idevImgSignCmd.Flags().Lookup("proxy"))
	viper.BindPFlag("idev.img.sign.insecure", idevImgSignCmd.Flags().Lookup("insecure"))
}

// idevImgSignCmd represents the sign command
var idevImgSignCmd = &cobra.Command{
	Use:           "sign",
	Short:         "Personalize DDI",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// flags
		xcode := viper.GetString("idev.img.sign.xcode")
		manifestPath := viper.GetString("idev.img.sign.manifest")
		boardID := viper.GetUint64("idev.img.sign.board-id")
		chipID := viper.GetUint64("idev.img.sign.chip-id")
		ecid := viper.GetUint64("idev.img.sign.ecid")
		apItems := viper.GetStringSlice("idev.img.sign.ap-item")
		nonce := viper.GetString("idev.img.sign.nonce")
		input := viper.GetString("idev.img.sign.input")
		output := viper.GetString("idev.img.sign.output")
		// verify flags
		if xcode != "" && manifestPath != "" {
			return fmt.Errorf("cannot specify both --xcode and --manifest")
		} else if xcode == "" && manifestPath == "" {
			return fmt.Errorf("must specify either --xcode or --manifest")
		} else if (boardID == 0 || chipID == 0 || ecid == 0 || nonce == "") && input == "" {
			return fmt.Errorf("must specify --board-id, --chip-id, --ecid AND --nonce")
		}

		personlID := make(map[string]any)

		if input != "" {
			dat, err := os.ReadFile(filepath.Clean(input))
			if err != nil {
				return fmt.Errorf("failed to read input file '%s': %w", input, err)
			}
			if err := json.Unmarshal(dat, &personlID); err != nil {
				return fmt.Errorf("failed to unmarshal input file '%s': %w", input, err)
			}
			// validate personlID
			if _, ok := personlID["BoardId"]; !ok {
				return errors.New("input JSON missing BoardId field")
			}
			if _, ok := personlID["ChipID"]; !ok {
				return errors.New("input JSON missing ChipID field")
			}
			if _, ok := personlID["UniqueChipID"]; !ok {
				return errors.New("input JSON missing UniqueChipID field")
			}
			if _, ok := personlID["ApNonce"]; !ok {
				return errors.New("input JSON missing ApNonce field")
			}
		} else {
			// NOTE: I have to store them as float64 because that's how Go decodes JSON numbers
			personlID["BoardId"] = float64(boardID)
			personlID["ChipID"] = float64(chipID)
			personlID["UniqueChipID"] = float64(ecid)
			personlID["ApNonce"] = nonce
			for _, ap := range apItems {
				personlID[ap] = uint64(0)
			}
		}

		if xcode != "" {
			xcodeVersion, err := utils.GetXCodeVersion(xcode)
			if err != nil {
				return fmt.Errorf("failed to get Xcode version: %w", err)
			}
			xcver, err := semver.NewVersion(xcodeVersion) // check
			if err != nil {
				return fmt.Errorf("failed to convert version into semver object")
			}
			var ddiPath string
			if xcver.LessThan(semver.Must(semver.NewVersion("16.0"))) {
				ddiPath = filepath.Join(xcode, "/Contents/Resources/CoreDeviceDDIs/iOS_DDI.dmg")
				if _, err := os.Stat(ddiPath); errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("failed to find iOS_DDI.dmg in '%s' (install NEW XCode.app or Xcode-beta.app)", xcode)
				}
			} else {
				ddiPath = "/Library/Developer/DeveloperDiskImages/iOS_DDI.dmg"
				if _, err := os.Stat(ddiPath); errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("failed to find iOS_DDI.dmg in '%s' (run `%s -runFirstLaunch` and try again)", ddiPath, filepath.Join(xcode, "Contents/Developer/usr/bin/xcodebuild"))
				}
			}
			utils.Indent(log.Info, 2)(fmt.Sprintf("Mounting %s", ddiPath))
			mountPoint, alreadyMounted, err := utils.MountDMG(ddiPath)
			if err != nil {
				return fmt.Errorf("failed to mount iOS_DDI.dmg: %w", err)
			}
			if alreadyMounted {
				utils.Indent(log.Info, 3)(fmt.Sprintf("%s already mounted", ddiPath))
			} else {
				defer func() {
					utils.Indent(log.Debug, 2)(fmt.Sprintf("Unmounting %s", ddiPath))
					if err := utils.Retry(3, 2*time.Second, func() error {
						return utils.Unmount(mountPoint, false)
					}); err != nil {
						log.Errorf("failed to unmount %s at %s: %v", ddiPath, mountPoint, err)
					}
				}()
			}
			manifestPath = filepath.Join(mountPoint, "Restore/BuildManifest.plist")
		}

		manifestData, err := os.ReadFile(manifestPath)
		if err != nil {
			return fmt.Errorf("failed to read BuildManifest.plist: %w", err)
		}
		buildManifest, err := plist.ParseBuildManifest(manifestData)
		if err != nil {
			return fmt.Errorf("failed to parse BuildManifest.plist: %w", err)
		}

		sigData, err := tss.Personalize(&tss.PersonalConfig{
			Proxy:         viper.GetString("idev.img.sign.proxy"),
			Insecure:      viper.GetBool("idev.img.sign.insecure"),
			PersonlID:     personlID,
			BuildManifest: buildManifest,
		})
		if err != nil {
			return fmt.Errorf("failed to personalize DDI: %w", err)
		}

		fname := fmt.Sprintf("%d.%d.%d.%s", uint64(personlID["BoardId"].(float64)), uint64(personlID["ChipID"].(float64)), uint64(personlID["UniqueChipID"].(float64)), "personalized.signature")
		if output != "" {
			if err := os.MkdirAll(output, 0750); err != nil {
				return fmt.Errorf("failed to create output folder '%s': %w", output, err)
			}
			fname = filepath.Join(output, fname)
		}

		log.Infof("Writing signature to %s", fname)
		if err := os.WriteFile(fname, sigData, 0644); err != nil {
			return fmt.Errorf("failed to write signature to %s: %w", output, err)
		}

		return nil
	},
}
