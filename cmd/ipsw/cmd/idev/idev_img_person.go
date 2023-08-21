/*
Copyright © 2023 blacktop

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
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	ImgCmd.AddCommand(idevImgPersonCmd)

	idevImgPersonCmd.Flags().StringP("xcode", "x", "/Applications/Xcode.app", "Path to Xcode.app")
	idevImgPersonCmd.Flags().StringP("manifest", "m", "", "BuildManifest.plist to use")
	idevImgPersonCmd.Flags().Uint64P("board-id", "b", 0, "Device ApBoardID")
	idevImgPersonCmd.Flags().Uint64P("chip-id", "c", 0, "Device ApChipID")
	idevImgPersonCmd.Flags().Uint64P("ecid", "e", 0, "Device ApECID")
	idevImgPersonCmd.Flags().StringP("nonce", "n", "", "Device ApNonce")
	idevImgPersonCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	idevImgPersonCmd.Flags().Bool("insecure", false, "do not verify ssl certs")
	idevImgPersonCmd.Flags().StringP("output", "o", "", "Folder to write signature to")
	idevImgPersonCmd.MarkFlagDirname("output")

	viper.BindPFlag("idev.img.person.xcode", idevImgPersonCmd.Flags().Lookup("xcode"))
	viper.BindPFlag("idev.img.person.manifest", idevImgPersonCmd.Flags().Lookup("manifest"))
	viper.BindPFlag("idev.img.person.board-id", idevImgPersonCmd.Flags().Lookup("board-id"))
	viper.BindPFlag("idev.img.person.chip-id", idevImgPersonCmd.Flags().Lookup("chip-id"))
	viper.BindPFlag("idev.img.person.ecid", idevImgPersonCmd.Flags().Lookup("ecid"))
	viper.BindPFlag("idev.img.person.nonce", idevImgPersonCmd.Flags().Lookup("nonce"))
	viper.BindPFlag("idev.img.person.output", idevImgPersonCmd.Flags().Lookup("output"))
	viper.BindPFlag("idev.img.person.proxy", idevImgPersonCmd.Flags().Lookup("proxy"))
	viper.BindPFlag("idev.img.person.insecure", idevImgPersonCmd.Flags().Lookup("insecure"))
}

// idevImgPersonCmd represents the person command
var idevImgPersonCmd = &cobra.Command{
	Use:           "person",
	Short:         "Personalize DDI",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = !viper.GetBool("color")

		// flags
		xcode := viper.GetString("idev.img.mount.xcode")
		manifestPath := viper.GetString("idev.img.mount.manifest")
		boardID := viper.GetUint64("idev.img.person.board-id")
		chipID := viper.GetUint64("idev.img.person.chip-id")
		ecid := viper.GetUint64("idev.img.person.ecid")
		nonce := viper.GetString("idev.img.person.nonce")
		output := viper.GetString("idev.img.person.output")
		// verify flags
		if xcode != "" && manifestPath != "" {
			return fmt.Errorf("cannot specify both --xcode and --manifest")
		} else if xcode == "" && manifestPath == "" {
			return fmt.Errorf("must specify either --xcode or --manifest")
		} else if boardID == 0 || chipID == 0 || ecid == 0 || nonce == "" {
			return fmt.Errorf("must specify --board-id, --chip-id, --ecid AND --nonce")
		}

		if xcode != "" {
			dmgPath := filepath.Join(xcode, "/Contents/Resources/CoreDeviceDDIs/iOS_DDI.dmg")
			if _, err := os.Stat(dmgPath); errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("failed to find iOS_DDI.dmg in '%s' (install NEW XCode.app or Xcode-beta.app)", xcode)
			}
			utils.Indent(log.Info, 2)(fmt.Sprintf("Mounting %s", dmgPath))
			mountPoint, alreadyMounted, err := utils.MountDMG(dmgPath)
			if err != nil {
				return fmt.Errorf("failed to mount iOS_DDI.dmg: %w", err)
			}
			if alreadyMounted {
				utils.Indent(log.Info, 3)(fmt.Sprintf("%s already mounted", dmgPath))
			} else {
				defer func() {
					utils.Indent(log.Debug, 2)(fmt.Sprintf("Unmounting %s", dmgPath))
					if err := utils.Retry(3, 2*time.Second, func() error {
						return utils.Unmount(mountPoint, false)
					}); err != nil {
						log.Errorf("failed to unmount %s at %s: %v", dmgPath, mountPoint, err)
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
			Proxy:    viper.GetString("idev.img.person.proxy"),
			Insecure: viper.GetBool("idev.img.person.insecure"),
			PersonlID: map[string]any{
				"BoardId":      boardID,
				"ChipID":       chipID,
				"UniqueChipID": ecid,
			},
			BuildManifest: buildManifest,
			Nonce:         nonce,
		})
		if err != nil {
			return fmt.Errorf("failed to personalize DDI: %w", err)
		}

		fname := fmt.Sprintf("%d.%d.%d.%s", boardID, chipID, ecid, "personalized.signature")
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
