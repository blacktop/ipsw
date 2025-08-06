/*
Copyright © 2025 blacktop

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

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/commands/device"
	"github.com/blacktop/ipsw/pkg/tss"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	ImgCmd.AddCommand(idevImgSignCmd)

	idevImgSignCmd.Flags().StringP("xcode", "x", "", "Path to Xcode.app")
	idevImgSignCmd.Flags().StringP("ddi-dmg", "d", "", "DDI.dmg to mount")
	idevImgSignCmd.Flags().StringP("ddi-folder", "f", "", "DDI folder (i.e. /Library/Developer/DeveloperDiskImages/iOS_DDI)")
	idevImgSignCmd.Flags().StringP("manifest", "m", "", "BuildManifest.plist to use")
	// idevImgSignCmd.Flags().Bool("backup", false, "Backup DDI files for offline use")
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
	viper.BindPFlag("idev.img.sign.ddi-dmg", idevImgSignCmd.Flags().Lookup("ddi-dmg"))
	viper.BindPFlag("idev.img.sign.ddi-folder", idevImgSignCmd.Flags().Lookup("ddi-folder"))
	viper.BindPFlag("idev.img.sign.manifest", idevImgSignCmd.Flags().Lookup("manifest"))
	// viper.BindPFlag("idev.img.sign.backup", idevImgSignCmd.Flags().Lookup("backup"))
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
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		// flags
		xcode := viper.GetString("idev.img.sign.xcode")
		ddiDmgPath := viper.GetString("idev.img.sign.ddi-dmg")
		ddiFolder := viper.GetString("idev.img.sign.ddi-folder")
		manifestPath := viper.GetString("idev.img.sign.manifest")
		// backup := viper.GetBool("idev.img.sign.backup")
		boardID := viper.GetUint64("idev.img.sign.board-id")
		chipID := viper.GetUint64("idev.img.sign.chip-id")
		ecid := viper.GetUint64("idev.img.sign.ecid")
		apItems := viper.GetStringSlice("idev.img.sign.ap-item")
		nonce := viper.GetString("idev.img.sign.nonce")
		input := viper.GetString("idev.img.sign.input")
		output := viper.GetString("idev.img.sign.output")
		// verify flags
		if (xcode != "" || ddiDmgPath != "" || ddiFolder != "") && manifestPath != "" {
			return fmt.Errorf("cannot specify both one of [--xcode, --ddi-dmg, --ddi-folder] AND --manifest")
		} else if xcode == "" && ddiDmgPath == "" && ddiFolder == "" && manifestPath == "" {
			return fmt.Errorf("must specify either one of [--xcode, --ddi-dmg, --ddi-folder] OR --manifest")
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

		ddi, err := device.GetDDIInfo(&device.DDIConfig{
			ImageType:  "Personalized",
			XCodePath:  xcode,
			DDIFolder:  ddiFolder,
			DDIDmgPath: ddiDmgPath,
		})
		if err != nil {
			return fmt.Errorf("failed to get DDI info: %w", err)
		}
		defer ddi.Clean()

		if ddi.BuildManifest == nil {
			return fmt.Errorf("failed to get BuildManifest")
		}

		// if backup {
		// 	if err := ddi.Backup(output); err != nil {
		// 		return fmt.Errorf("failed to backup DDI: %w", err)
		// 	}
		// }

		sigData, err := tss.Personalize(&tss.PersonalConfig{
			Proxy:         viper.GetString("idev.img.sign.proxy"),
			Insecure:      viper.GetBool("idev.img.sign.insecure"),
			PersonlID:     personlID,
			BuildManifest: ddi.BuildManifest,
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
