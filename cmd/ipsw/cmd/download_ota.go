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

	otaDLCmd.Flags().BoolP("ios13", "", false, "Download iOS 13.x OTAs (defaults to iOS14)")
	otaDLCmd.Flags().BoolP("dyld", "", false, "Extract dyld_shared_cache from remote OTA zip")
	// otaDLCmd.Flags().BoolP("kernel", "k", false, "Extract kernelcache from remote OTA zip")
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
		confirm, _ := cmd.Flags().GetBool("yes")
		skipAll, _ := cmd.Flags().GetBool("skip-all")

		// filters
		device, _ := cmd.Flags().GetString("device")
		doDownload, _ := cmd.Flags().GetStringArray("white-list")
		doNotDownload, _ := cmd.Flags().GetStringArray("black-list")

		ios13, _ := cmd.Flags().GetBool("ios13")

		remoteDyld, _ := cmd.Flags().GetBool("dyld")
		// TODO: add kernel back in once we have a pure Go lzfse
		// remoteKernel, _ := cmd.Flags().GetBool("kernel")

		if remoteDyld && !ios13 {
			// if (remoteDyld || remoteKernel) && !ios13 {
			log.Fatal("--dyld currently not supported on iOS14.x")
			// log.Fatal("--kernel OR --dyld currently not supported on iOS14.x")
		}

		otaXML, err := download.NewOTA(proxy, insecure, ios13)
		if err != nil {
			return errors.Wrap(err, "failed to create itunes API")
		}

		otas := otaXML.GetOTAs(device, doDownload, doNotDownload)
		if len(otas) == 0 {
			log.Fatal(fmt.Sprintf("no OTAs match device %s %s", device, doDownload))
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
			if remoteDyld && ios13 {
				// if (remoteDyld || remoteKernel) && ios13 {
				for _, o := range otas {
					log.WithFields(log.Fields{
						"device":  o.SupportedDevices[0],
						"build":   o.Build,
						"version": o.DocumentationID,
					}).Info("Parsing remote OTA")
					zr, err := download.NewRemoteZipReader(o.BaseURL+o.RelativePath, &download.RemoteConfig{
						Proxy:    proxy,
						Insecure: insecure,
					})
					if err != nil {
						return errors.Wrap(err, "failed to open remote zip to OTA")
					}
					if remoteDyld {
						log.Info("Extracting remote dyld_shared_cache (can be a bit CPU intensive)")
						err = ota.RemoteExtract(zr, "dyld_shared_cache_arm")
						if err != nil {
							return errors.Wrap(err, "failed to download dyld_shared_cache from remote ota")
						}
					}
					// if remoteKernel {
					// 	log.Info("Extracting remote kernelcache")
					// 	err = kernelcache.RemoteParse(zr)
					// 	if err != nil {
					// 		return errors.Wrap(err, "failed to download kernelcache from remote ota")
					// 	}
					// }
				}
			} else {
				downloader := download.NewDownload(proxy, insecure, skipAll)
				for _, o := range otas {
					url := o.BaseURL + o.RelativePath
					destName := strings.Replace(path.Base(url), ",", "_", -1)
					if _, err := os.Stat(destName); os.IsNotExist(err) {
						log.WithFields(log.Fields{
							"device":  o.SupportedDevices[0],
							"build":   o.Build,
							"version": o.DocumentationID,
						}).Info("Getting OTA")
						// download file
						downloader.URL = url
						downloader.DestName = destName
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
