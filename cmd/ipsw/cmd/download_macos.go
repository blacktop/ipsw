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
	"path/filepath"

	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	downloadCmd.AddCommand(macosCmd)

	macosCmd.Flags().BoolP("info", "i", false, "Show latest macOS version")
	macosCmd.Flags().BoolP("installer", "", false, "Show latest macOS installers")
	// macosCmd.Flags().StringP("work-dir", "w", "", "macOS installer creator working directory")
	macosCmd.Flags().BoolP("kernel", "k", false, "Extract kernelcache from remote IPSW")
}

// macosCmd represents the macos command
var macosCmd = &cobra.Command{
	Use:   "macos",
	Short: "Download and parse macOS IPSWs",
	RunE: func(cmd *cobra.Command, args []string) error {
		var err error
		var builds []download.Build
		var filteredBuilds []download.Build

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		// settings
		proxy, _ := cmd.Flags().GetString("proxy")
		insecure, _ := cmd.Flags().GetBool("insecure")
		confirm, _ := cmd.Flags().GetBool("yes")
		skipAll, _ := cmd.Flags().GetBool("skip-all")
		removeCommas, _ := cmd.Flags().GetBool("remove-commas")
		// filters
		device, _ := cmd.Flags().GetString("device")
		// model, _ := cmd.Flags().GetString("model")
		// version, _ := cmd.Flags().GetString("version")
		// build, _ := cmd.Flags().GetString("build")
		doDownload, _ := cmd.Flags().GetStringArray("white-list")
		doNotDownload, _ := cmd.Flags().GetStringArray("black-list")

		iosInfo, _ := cmd.Flags().GetBool("info")
		showInstallers, _ := cmd.Flags().GetBool("installer")
		// workDir, _ := cmd.Flags().GetString("work-dir")
		remoteKernel, _ := cmd.Flags().GetBool("kernel")

		var destPath string
		if len(args) > 0 {
			destPath = filepath.Clean(args[0])
		}

		if showInstallers {
			if prods, err := download.GetProductInfo(); err != nil {
				log.Error(err.Error())
			} else {
				fmt.Println(prods)
				// for _, prod := range prods {
				// 	// if prod.ProductID == "071-14766" {
				// 	if prod.ProductID == "001-68446" {
				// 		if err := prod.DownloadInstaller(workDir, proxy, insecure, skipAll); err != nil {
				// 			log.Error(err.Error())
				// 		}
				// 	}
				// }
			}
			return nil
		}

		macOS, err := download.NewMacOsXML()
		if err != nil {
			return errors.Wrap(err, "failed to create itunes API")
		}

		if iosInfo {
			latestVersion, err := macOS.GetLatestVersion()
			if err != nil {
				return errors.Wrap(err, "failed to get latest iOS version")
			}
			fmt.Print(latestVersion)
			return nil
		}

		builds, err = macOS.GetLatestBuilds(device)
		if err != nil {
			return errors.Wrap(err, "failed to get the latest builds")
		}

		for _, v := range builds {
			if len(doDownload) > 0 {
				if utils.StrSliceContains(doDownload, v.Identifier) {
					filteredBuilds = append(filteredBuilds, v)
				}
			} else if len(doNotDownload) > 0 {
				if !utils.StrSliceContains(doNotDownload, v.Identifier) {
					filteredBuilds = append(filteredBuilds, v)
				}
			} else {
				filteredBuilds = append(filteredBuilds, v)
			}
		}

		if len(filteredBuilds) == 0 {
			log.Fatal(fmt.Sprintf("no IPSWs match device %s %s", device, doDownload))
		}

		log.Debug("URLs to Download:")
		for _, b := range filteredBuilds {
			utils.Indent(log.Debug, 1)(b.FirmwareURL)
		}

		cont := true
		if !confirm {
			cont = false
			prompt := &survey.Confirm{
				Message: fmt.Sprintf("You are about to download %d ipsw files. Continue?", len(filteredBuilds)),
			}
			survey.AskOne(prompt, &cont)
		}

		if cont {
			if remoteKernel {
				for _, build := range filteredBuilds {
					log.WithFields(log.Fields{
						"device":  build.Identifier,
						"build":   build.BuildVersion,
						"version": build.ProductVersion,
					}).Info("Getting Kernelcache")
					zr, err := download.NewRemoteZipReader(build.FirmwareURL, &download.RemoteConfig{
						Proxy:    proxy,
						Insecure: insecure,
					})
					if err != nil {
						return errors.Wrap(err, "failed to open remote zip to OTA")
					}
					log.Info("Extracting remote kernelcache")
					err = kernelcache.RemoteParse(zr, destPath)
					if err != nil {
						return errors.Wrap(err, "failed to download kernelcache from remote ota")
					}
				}
			} else {
				downloader := download.NewDownload(proxy, insecure, skipAll, Verbose)
				for _, build := range filteredBuilds {
					destName := getDestName(build.FirmwareURL, removeCommas)
					if _, err := os.Stat(destName); os.IsNotExist(err) {
						log.WithFields(log.Fields{
							"device":  build.Identifier,
							"build":   build.BuildVersion,
							"version": build.ProductVersion,
						}).Info("Getting IPSW")
						// download file
						downloader.URL = build.FirmwareURL
						downloader.Sha1 = build.FirmwareSHA1
						downloader.DestName = destName
						err = downloader.Do()
						if err != nil {
							return errors.Wrap(err, "failed to download file")
						}
						// append sha1 and filename to checksums file
						f, err := os.OpenFile("checksums.txt.sha1", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
						if err != nil {
							return errors.Wrap(err, "failed to open checksums.txt.sha1")
						}
						defer f.Close()
						if _, err = f.WriteString(build.FirmwareSHA1 + "  " + destName + "\n"); err != nil {
							return errors.Wrap(err, "failed to write to checksums.txt.sha1")
						}
					} else {
						log.Warnf("ipsw already exists: %s", destName)
					}
				}
			}
		}

		return nil
	},
}
