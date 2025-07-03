//go:build libusb

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
package cmd

import (
	"archive/zip"
	"crypto/aes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/usb/pongo"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(pongoCmd)
	pongoCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	pongoCmd.Flags().Bool("insecure", false, "do not verify ssl certs")
	pongoCmd.Flags().BoolP("remote", "r", false, "Use remote IPSW")
	pongoCmd.Flags().BoolP("decrypt", "d", false, "Extract and decrypt im4p files")
	pongoCmd.Flags().StringP("output", "o", "", "Folder to write JSON to")
	pongoCmd.MarkFlagDirname("output")
	viper.BindPFlag("pongo.proxy", pongoCmd.Flags().Lookup("proxy"))
	viper.BindPFlag("pongo.insecure", pongoCmd.Flags().Lookup("insecure"))
	viper.BindPFlag("pongo.remote", pongoCmd.Flags().Lookup("remote"))
	viper.BindPFlag("pongo.decrypt", pongoCmd.Flags().Lookup("decrypt"))
	viper.BindPFlag("pongo.output", pongoCmd.Flags().Lookup("output"))
}

// pongoCmd represents the pongo command
var pongoCmd = &cobra.Command{
	Use:           "pongo <IPSW>",
	Aliases:       []string{"p"},
	Short:         "PongoOS Terminal",
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		var err error
		var i *info.Info
		var destPath string
		var kbags *img4.KeyBags

		if viper.GetBool("pongo.remote") {
			// Get handle to remote IPSW zip
			zr, err := download.NewRemoteZipReader(args[0], &download.RemoteConfig{
				Proxy:    viper.GetString("pongo.proxy"),
				Insecure: viper.GetBool("pongo.insecure"),
			})
			if err != nil {
				return fmt.Errorf("unable to download remote zip: %v", err)
			}

			i, err = info.ParseZipFiles(zr.File)
			if err != nil {
				return fmt.Errorf("failed to parse plists in remote zip: %v", err)
			}
			folder, err := i.GetFolder()
			if err != nil {
				log.Errorf("failed to get folder from remote zip metadata: %v", err)
			}
			destPath = filepath.Join(filepath.Clean(viper.GetString("pongo.output")), folder)

			log.Info("Extracting im4p kbags")
			kbags, err = img4.GetKeybagsFromIPSW(zr.File, img4.KeybagMetaData{
				Type:    i.Plists.Type,
				Version: i.Plists.BuildManifest.ProductVersion,
				Build:   i.Plists.BuildManifest.ProductBuildVersion,
				Devices: i.Plists.Restore.SupportedProductTypes,
			}, "")
			if err != nil {
				return fmt.Errorf("failed to parse im4p kbags: %v", err)
			}

			if viper.GetBool("pongo.decrypt") {
				for _, kbag := range kbags.Files {
					if _, err := utils.SearchZip(zr.File, regexp.MustCompile(kbag.Name), destPath, true, true); err != nil {
						return fmt.Errorf("failed to extract files matching pattern in remote IPSW: %v", err)
					}
				}
			}
		} else {
			ipswPath := filepath.Clean(args[0])

			if _, err := os.Stat(ipswPath); os.IsNotExist(err) {
				return fmt.Errorf("file %s does not exist", ipswPath)
			}

			i, err = info.Parse(ipswPath)
			if err != nil {
				return fmt.Errorf("failed to parse plists in IPSW: %v", err)
			}
			folder, err := i.GetFolder()
			if err != nil {
				log.Errorf("failed to get folder from remote zip metadata: %v", err)
			}
			destPath = filepath.Join(filepath.Clean(viper.GetString("pongo.output")), folder)

			zr, err := zip.OpenReader(ipswPath)
			if err != nil {
				return fmt.Errorf("failed to open zip: %v", err)
			}
			defer zr.Close()

			log.Info("Extracting im4p kbags")
			kbags, err = img4.GetKeybagsFromIPSW(zr.File, img4.KeybagMetaData{
				Type:    i.Plists.Type,
				Version: i.Plists.BuildManifest.ProductVersion,
				Build:   i.Plists.BuildManifest.ProductBuildVersion,
				Devices: i.Plists.Restore.SupportedProductTypes,
			}, "")
			if err != nil {
				return fmt.Errorf("failed to parse IPSW im4p kbags: %v", err)
			}

			if viper.GetBool("pongo.decrypt") {
				for _, kbag := range kbags.Files {
					if _, err := utils.SearchZip(zr.File, regexp.MustCompile(fmt.Sprintf(".*%s$", kbag.Name)), destPath, true, false); err != nil {
						return fmt.Errorf("failed to extract files matching pattern in remote IPSW: %v", err)
					}
				}
			}
		}

		cli, err := pongo.NewClient()
		if err != nil {
			return fmt.Errorf("failed to connect to pongo: %w", err)
		}
		defer cli.Close()

		if err := cli.SendCommand("sep auto"); err != nil {
			return fmt.Errorf("failed to send command: %w", err)
		}

		for idx, kbag := range kbags.Files {
			utils.Indent(log.WithFields(log.Fields{"file": kbag.Name}).Info, 2)("Decrypting Keybag")

			if len(kbag.Keybags) != 2 {
				return fmt.Errorf("failed decrypt keybags (bad input): expected keybags to have prod and dev kbags: len=%d", len(kbag.Keybags))
			}

			if err := cli.SendCommand(
				fmt.Sprintf("sep decrypt %s%s", hex.EncodeToString(kbag.Keybags[0].IV), hex.EncodeToString(kbag.Keybags[0].Key)),
			); err != nil {
				return fmt.Errorf("failed to send command: %v", err)
			}

			time.Sleep(1 * time.Second)

			out, err := cli.GetStdOut()
			if err != nil {
				return fmt.Errorf("failed to get stdout: %v", err)
			}

			parts := strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n")
			found := false
			var ivkey string
			for _, part := range parts {
				if strings.HasPrefix(part, "kbag out: ") {
					found = true
					ivkey = strings.TrimPrefix(part, "kbag out: ")
					break
				}
			}
			if !found {
				return fmt.Errorf("got unexpected output: should have found line with prefex 'kbag out: %s", out)
			}

			ivKeyBytes, err := hex.DecodeString(ivkey)
			if err != nil {
				return fmt.Errorf("failed to decode iv+key string: %v", err)
			}
			kbags.Files[idx].Keybags = append(kbags.Files[idx].Keybags, img4.Keybag{
				IV:   ivKeyBytes[:aes.BlockSize],
				Key:  ivKeyBytes[aes.BlockSize:],
				Type: img4.DECRYPTED,
			})
		}

		if viper.GetBool("pongo.decrypt") {
			for _, kbag := range kbags.Files {
				fname := filepath.Join(destPath, kbag.Name)
				utils.Indent(log.Info, 2)(fmt.Sprintf("Decrypting file to %s", fname+".dec"))
				if err := img4.DecryptPayload(fname, fname+".dec", kbag.Keybags[2].IV, kbag.Keybags[2].Key); err != nil {
					return fmt.Errorf("failed to decrypt payload: %v", err)
				}
			}
		}

		kbJSON, err := json.Marshal(kbags)
		if err != nil {
			return fmt.Errorf("failed to marshal keybags: %v", err)
		}

		os.Mkdir(destPath, 0770)
		log.Infof("Writing keybags to %s", filepath.Join(destPath, "kbags.json"))
		if err := os.WriteFile(filepath.Join(destPath, "kbags.json"), kbJSON, 0660); err != nil {
			return fmt.Errorf("failed to write %s: %v", filepath.Join(destPath, "kbags.json"), err)
		}

		return nil
	},
}
