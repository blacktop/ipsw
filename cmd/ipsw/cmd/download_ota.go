/*
Copyright © 2020 blacktop

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
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/ota"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	downloadCmd.AddCommand(otaDLCmd)

	otaDLCmd.Flags().BoolP("dyld", "", false, "Extract dyld_shared_cache from remote zip")
}

// otaDLCmd represents the ota download command
var otaDLCmd = &cobra.Command{
	Use:   "ota",
	Short: "Download OTA betas",
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		proxy, _ := cmd.Flags().GetString("proxy")
		insecure, _ := cmd.Flags().GetBool("insecure")
		skip, _ := cmd.Flags().GetBool("yes")

		device, _ := cmd.Flags().GetString("device")
		doDownload, _ := cmd.Flags().GetStringArray("white-list")
		doNotDownload, _ := cmd.Flags().GetStringArray("black-list")

		remote, _ := cmd.Flags().GetBool("dyld")

		var otas []download.OtaAsset
		var filteredOtas []download.OtaAsset

		otaXML, err := download.NewOTA(proxy, insecure)
		if err != nil {
			return errors.Wrap(err, "failed to create itunes API")
		}

		for _, asset := range otaXML.Assets {
			if len(asset.ReleaseType) == 0 {
				if len(device) > 0 {
					if strings.EqualFold(device, asset.SupportedDevices[0]) {
						otas = append(otas, asset)
					}
				} else {
					otas = append(otas, asset)
				}

			}
		}

		for _, o := range otas {
			if len(doDownload) > 0 {
				if utils.StrSliceContains(doDownload, o.SupportedDevices[0]) {
					filteredOtas = append(filteredOtas, o)
				}
			} else if len(doNotDownload) > 0 {
				if !utils.StrSliceContains(doNotDownload, o.SupportedDevices[0]) {
					filteredOtas = append(filteredOtas, o)
				}
			} else {
				filteredOtas = append(filteredOtas, o)
			}
		}

		log.Debug("URLs to Download:")
		for _, o := range otas {
			utils.Indent(log.Debug, 2)(o.BaseURL + o.RelativePath)
		}

		cont := true
		if !skip {
			cont = false
			prompt := &survey.Confirm{
				Message: fmt.Sprintf("You are about to download %d ipsw files. Continue?", len(otas)),
			}
			survey.AskOne(prompt, &cont)
		}

		if cont {
			if remote {
				for _, o := range otas {
					zr, err := download.NewRemoteZipReader(o.BaseURL+o.RelativePath, &download.RemoteConfig{
						Proxy:    proxy,
						Insecure: insecure,
					})
					if err != nil {
						return errors.Wrap(err, "failed to download dyld_shared_cache from remote ota")
					}
					err = ota.RemoteExtract(zr, "dyld_shared_cache_arm")
				}
			} else {
				downloader := download.NewDownload(proxy, insecure)
				for _, o := range otas {
					url := o.BaseURL + o.RelativePath
					destName := strings.Replace(path.Base(url), ",", "_", -1)
					if _, err := os.Stat(destName); os.IsNotExist(err) {

						log.WithFields(log.Fields{
							"device":  o.SupportedDevices[0],
							"build":   o.Build,
							"version": o.OSVersion,
						}).Info("Getting OTA")
						// download file
						downloader.URL = url
						err = downloader.Do()
						if err != nil {
							return errors.Wrap(err, "failed to download file")
						}
					} else {
						log.Warnf("ota already exists: %s", destName)
					}
				}
			}
		}

		return nil
	},
}
