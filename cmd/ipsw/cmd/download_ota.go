/*
Copyright © 2021 blacktop

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
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/blacktop/ipsw/pkg/ota"
	"github.com/spf13/cobra"
)

func init() {
	downloadCmd.AddCommand(otaDLCmd)

	otaDLCmd.Flags().BoolP("release", "r", false, "Download Release (non-beta) OTAs")
	otaDLCmd.Flags().BoolP("dyld", "", false, "Extract dyld_shared_cache from remote OTA zip")
	otaDLCmd.Flags().BoolP("kernel", "k", false, "Extract kernelcache from remote OTA zip")
}

// otaDLCmd represents the ota download command
var otaDLCmd = &cobra.Command{
	Use:          "ota [options]",
	Short:        "Download OTA betas",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		proxy, _ := cmd.Flags().GetString("proxy")
		insecure, _ := cmd.Flags().GetBool("insecure")
		confirm, _ := cmd.Flags().GetBool("yes")
		skipAll, _ := cmd.Flags().GetBool("skip-all")

		// filters
		device, _ := cmd.Flags().GetString("device")
		doDownload, _ := cmd.Flags().GetStringArray("white-list")
		doNotDownload, _ := cmd.Flags().GetStringArray("black-list")

		release, _ := cmd.Flags().GetBool("release")

		remoteDyld, _ := cmd.Flags().GetBool("dyld")
		remoteKernel, _ := cmd.Flags().GetBool("kernel")

		otaXML, err := download.NewOTA(proxy, insecure, release)
		if err != nil {
			return fmt.Errorf("failed to parse remote OTA XML: %v", err)
		}

		var otas []download.OtaAsset
		if len(device) > 0 {
			o, err := otaXML.GetOtaForDevice(device, "")
			if err != nil {
				return fmt.Errorf("failed to get OTA asset for device %s: %v", device, err)
			}
			otas = append(otas, o)
		} else {
			log.Info("Querying Apple servers...")
			otas = otaXML.GetOTAs(device, doDownload, doNotDownload)
			if len(otas) == 0 {
				log.Fatal(fmt.Sprintf("no OTAs match device %s %s", device, doDownload))
			}
		}

		log.Debug("URLs to Download:")
		for _, o := range otas {
			utils.Indent(log.Debug, 2)(o.BaseURL + o.RelativePath)
		}

		cont := true
		if !confirm {
			cont = false
			prompt := &survey.Confirm{
				Message: fmt.Sprintf("You are about to download %d OTA files. Continue?", len(otas)),
			}
			survey.AskOne(prompt, &cont)
		}

		if cont {
			if remoteDyld || remoteKernel {
				for _, o := range otas {
					log.WithFields(log.Fields{
						"device":  strings.Join(o.SupportedDevices, " "),
						"build":   o.Build,
						"version": o.DocumentationID,
					}).Info("Parsing remote OTA")
					zr, err := download.NewRemoteZipReader(o.BaseURL+o.RelativePath, &download.RemoteConfig{
						Proxy:    proxy,
						Insecure: insecure,
					})
					if err != nil {
						return fmt.Errorf("failed to open remote zip to OTA: %v", err)
					}
					if remoteDyld {
						log.Info("Extracting remote dyld_shared_cache (can be a bit CPU intensive)")
						err = ota.RemoteExtract(zr, "dyld_shared_cache_arm")
						if err != nil {
							return fmt.Errorf("failed to download dyld_shared_cache from remote ota: %v", err)
						}
					}
					if remoteKernel {
						log.Info("Extracting remote kernelcache")
						err = kernelcache.RemoteParse(zr)
						if err != nil {
							return fmt.Errorf("failed to download kernelcache from remote ota: %v", err)
						}
					}
				}
			} else {
				downloader := download.NewDownload(proxy, insecure, skipAll)
				for _, o := range otas {
					url := o.BaseURL + o.RelativePath
					destName := strings.Replace(path.Base(url), ",", "_", -1)
					if _, err := os.Stat(destName); os.IsNotExist(err) {
						log.WithFields(log.Fields{
							"device":  strings.Join(o.SupportedDevices, " "),
							"build":   o.Build,
							"version": o.DocumentationID,
						}).Info("Getting OTA")
						// download file
						downloader.URL = url
						downloader.DestName = destName
						err = downloader.Do()
						if err != nil {
							return fmt.Errorf("failed to download file: %v", err)
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
