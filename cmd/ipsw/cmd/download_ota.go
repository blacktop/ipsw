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
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/blacktop/ipsw/pkg/ota"
	semver "github.com/hashicorp/go-version"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	downloadCmd.AddCommand(otaDLCmd)

	otaDLCmd.Flags().StringP("platform", "p", "ios", "Platform to download (ios, macos, watchos, tvos, audioos)")
	viper.BindPFlag("download.ota.platform", otaDLCmd.Flags().Lookup("platform"))
	otaDLCmd.Flags().Bool("beta", false, "Download Beta OTAs")
	viper.BindPFlag("download.ota.beta", otaDLCmd.Flags().Lookup("beta"))
	otaDLCmd.Flags().Bool("dyld", false, "Extract dyld_shared_cache from remote OTA zip")
	viper.BindPFlag("download.ota.dyld", otaDLCmd.Flags().Lookup("dyld"))
	otaDLCmd.Flags().Bool("kernel", false, "Extract kernelcache from remote OTA zip")
	viper.BindPFlag("download.ota.kernel", otaDLCmd.Flags().Lookup("kernel"))
	otaDLCmd.Flags().Bool("info", false, "Show all the latest OTAs available")
	viper.BindPFlag("download.ota.info", otaDLCmd.Flags().Lookup("info"))
	otaDLCmd.Flags().String("info-type", "", "OS type to show OTAs for")
	viper.BindPFlag("download.ota.info-type", otaDLCmd.Flags().Lookup("info-type"))
}

// otaDLCmd represents the ota download command
var otaDLCmd = &cobra.Command{
	Use:          "ota [options]",
	Short:        "Download OTAs",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		var err error
		var ver *semver.Version

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		viper.BindPFlag("download.white-list", cmd.Flags().Lookup("white-list"))
		viper.BindPFlag("download.black-list", cmd.Flags().Lookup("black-list"))
		viper.BindPFlag("download.confirm", cmd.Flags().Lookup("confirm"))
		viper.BindPFlag("download.skip-all", cmd.Flags().Lookup("skip-all"))
		viper.BindPFlag("download.remove-commas", cmd.Flags().Lookup("remove-commas"))
		viper.BindPFlag("download.device", cmd.Flags().Lookup("device"))
		viper.BindPFlag("download.model", cmd.Flags().Lookup("model"))
		viper.BindPFlag("download.version", cmd.Flags().Lookup("version"))
		viper.BindPFlag("download.build", cmd.Flags().Lookup("build"))

		// settings
		proxy := viper.GetString("download.proxy")
		insecure := viper.GetBool("download.insecure")
		confirm := viper.GetBool("download.confirm")
		skipAll := viper.GetBool("download.skip-all")
		removeCommas := viper.GetBool("download.remove-commas")
		// filters
		device := viper.GetString("download.device")
		model := viper.GetString("download.model")
		version := viper.GetString("download.version")
		build := viper.GetString("download.build")
		doDownload := viper.GetStringSlice("download.white-list")
		doNotDownload := viper.GetStringSlice("download.black-list")
		// flags
		platform := viper.GetString("download.ota.platform")
		getBeta := viper.GetBool("download.ota.beta")
		remoteDyld := viper.GetBool("download.ota.dyld")
		remoteKernel := viper.GetBool("download.ota.kernel")
		otaInfo := viper.GetBool("download.ota.info")
		otaInfoType := viper.GetString("download.ota.info-type")

		// Query for asset sets
		as, err := download.GetAssetSets(proxy, insecure)
		if err != nil {
			log.Fatal(err.Error())
		}

		/****************
		 * GET OTA INFO *
		 ****************/
		if otaInfo {
			if len(device) > 0 {
				log.WithField("device", device).Info("OTAs")
				for _, asset := range as.ForDevice(device) {
					utils.Indent(log.WithFields(log.Fields{
						"posting_date":    asset.PostingDate,
						"expiration_date": asset.ExpirationDate,
					}).Info, 2)(asset.ProductVersion)
				}
			} else {
				if len(otaInfoType) == 0 {
					prompt := &survey.Select{
						Message: "Choose an OS type:",
						Options: []string{"iOS", "macOS"},
					}
					survey.AskOne(prompt, &otaInfoType)
				} else {
					if !utils.StrSliceContains([]string{"iOS", "macOS"}, otaInfoType) {
						log.Fatal("you must supply a valid --info-type flag: (iOS, macOS)")
					}
				}
				log.WithField("type", otaInfoType).Info("OTAs")
				if otaInfoType == "iOS" {
					log.Warn("⚠️  This includes: iOS, iPadOS, watchOS, tvOS and audioOS (you can filter by adding the --device flag)")
				}
				for _, asset := range as.AssetSets[otaInfoType] {
					utils.Indent(log.WithFields(log.Fields{
						"posting_date":    asset.PostingDate,
						"expiration_date": asset.ExpirationDate,
					}).Info, 2)(asset.ProductVersion)
				}
			}
			return nil
		}

		// if len(version) > 0 && len(build) > 0 {
		// 	log.Fatal("you cannot supply a --version AND a --build (they are mutually exclusive)")
		// }

		if !utils.StrSliceContains(
			[]string{"ios", "macos", "watchos", "tvos", "audioos"}, strings.ToLower(platform)) {
			log.Fatal("you must supply a valid --platform flag. Choices are: ios, macos, watchos, tvos and audioos")
		}

		var destPath string
		if len(args) > 0 {
			destPath = filepath.Clean(args[0])
		}

		if len(version) > 0 {
			ver, err = semver.NewVersion(version)
			if err != nil {
				log.Fatal("failed to convert version into semver object")
			}
		}

		otaXML, err := download.NewOTA(as, download.OtaConf{
			Platform:        strings.ToLower(platform),
			Beta:            getBeta,
			Device:          device,
			Model:           model,
			Version:         ver,
			Build:           build,
			DeviceWhiteList: doDownload,
			DeviceBlackList: doNotDownload,
			Proxy:           proxy,
			Insecure:        insecure,
		})
		if err != nil {
			return fmt.Errorf("failed to parse remote OTA XML: %v", err)
		}
		// otas := otaXML.FilterOtaAssets(doDownload, doNotDownload)
		// if len(otas) == 0 {
		// 	log.Fatal(fmt.Sprintf("no OTAs match device %s %s", device, doDownload))
		// }
		otas, err := otaXML.GetPallasOTAs()
		if err != nil {
			return err
		}
		// for _, o := range otas {
		// 	log.WithFields(log.Fields{
		// 		"device":  strings.Join(o.SupportedDevices, " "),
		// 		"build":   o.Build,
		// 		"version": o.OSVersion,
		// 		// "url":     o.RelativePath,
		// 	}).Info("OTA")
		// }
		// return nil
		// var otas []download.OtaAsset
		// if len(device) > 0 {
		// 	o, err := otaXML.GetOtaForDevice(device, model)
		// 	if err != nil {
		// 		return fmt.Errorf("failed to get OTA asset for device %s: %v", device, err)
		// 	}
		// 	otas = append(otas, o)
		// } else {
		// 	log.Info("Querying Apple servers...")
		// 	otas = otaXML.FilterOtaAssets(doDownload, doNotDownload)
		// 	if len(otas) == 0 {
		// 		log.Fatal(fmt.Sprintf("no OTAs match device %s %s", device, doDownload))
		// 	}
		// }

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
						err = kernelcache.RemoteParse(zr, destPath)
						if err != nil {
							return fmt.Errorf("failed to download kernelcache from remote ota: %v", err)
						}
					}
				}
			} else {
				downloader := download.NewDownload(proxy, insecure, skipAll, Verbose)
				for _, o := range otas {
					url := o.BaseURL + o.RelativePath
					destName := getDestName(url, removeCommas)
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
