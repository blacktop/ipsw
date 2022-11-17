/*
Copyright © 2018-2022 blacktop

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
package download

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/blacktop/ipsw/pkg/ota"
	"github.com/dustin/go-humanize"
	semver "github.com/hashicorp/go-version"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DownloadCmd.AddCommand(otaDLCmd)

	otaDLCmd.Flags().StringP("platform", "p", "", "Platform to download (ios, watchos, tvos, audioos || accessory, macos, recovery)")
	otaDLCmd.Flags().Bool("beta", false, "Download Beta OTAs")
	otaDLCmd.Flags().Bool("rsr", false, "Download Rapid Security Response OTAs")
	otaDLCmd.Flags().BoolP("kernel", "k", false, "Extract kernelcache from remote OTA zip")
	otaDLCmd.Flags().Bool("dyld", false, "Extract dyld_shared_cache(s) from remote OTA zip")
	otaDLCmd.Flags().BoolP("urls", "u", false, "Dump URLs only")
	otaDLCmd.Flags().BoolP("json", "j", false, "Dump URLs as JSON only")
	otaDLCmd.Flags().StringArrayP("dyld-arch", "a", []string{}, "dyld_shared_cache architecture(s) to remote extract")
	otaDLCmd.Flags().Bool("driver-kit", false, "Extract DriverKit dyld_shared_cache(s) from remote OTA zip")
	otaDLCmd.Flags().String("pattern", "", "Download remote files that match regex")
	otaDLCmd.Flags().BoolP("flat", "f", false, "Do NOT perserve directory structure when downloading with --pattern")
	otaDLCmd.Flags().Bool("info", false, "Show all the latest OTAs available")
	otaDLCmd.Flags().String("info-type", "", "OS type to show OTAs for")
	otaDLCmd.Flags().StringP("output", "o", "", "Folder to download files to")
	viper.BindPFlag("download.ota.platform", otaDLCmd.Flags().Lookup("platform"))
	viper.BindPFlag("download.ota.beta", otaDLCmd.Flags().Lookup("beta"))
	viper.BindPFlag("download.ota.rsr", otaDLCmd.Flags().Lookup("rsr"))
	viper.BindPFlag("download.ota.dyld", otaDLCmd.Flags().Lookup("dyld"))
	viper.BindPFlag("download.ota.urls", otaDLCmd.Flags().Lookup("urls"))
	viper.BindPFlag("download.ota.json", otaDLCmd.Flags().Lookup("json"))
	viper.BindPFlag("download.ota.dyld-arch", otaDLCmd.Flags().Lookup("dyld-arch"))
	viper.BindPFlag("download.ota.driver-kit", otaDLCmd.Flags().Lookup("driver-kit"))
	viper.BindPFlag("download.ota.kernel", otaDLCmd.Flags().Lookup("kernel"))
	viper.BindPFlag("download.ota.pattern", otaDLCmd.Flags().Lookup("pattern"))
	viper.BindPFlag("download.ota.flat", otaDLCmd.Flags().Lookup("flat"))
	viper.BindPFlag("download.ota.info", otaDLCmd.Flags().Lookup("info"))
	viper.BindPFlag("download.ota.info-type", otaDLCmd.Flags().Lookup("info-type"))
	viper.BindPFlag("download.ota.output", otaDLCmd.Flags().Lookup("output"))
}

// otaDLCmd represents the ota download command
var otaDLCmd = &cobra.Command{
	Use:           "ota [options]",
	Short:         "Download OTAs",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		var err error
		var ver *semver.Version

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		viper.BindPFlag("download.proxy", cmd.Flags().Lookup("proxy"))
		viper.BindPFlag("download.insecure", cmd.Flags().Lookup("insecure"))
		viper.BindPFlag("download.confirm", cmd.Flags().Lookup("confirm"))
		viper.BindPFlag("download.skip-all", cmd.Flags().Lookup("skip-all"))
		viper.BindPFlag("download.resume-all", cmd.Flags().Lookup("resume-all"))
		viper.BindPFlag("download.restart-all", cmd.Flags().Lookup("restart-all"))
		viper.BindPFlag("download.remove-commas", cmd.Flags().Lookup("remove-commas"))
		viper.BindPFlag("download.white-list", cmd.Flags().Lookup("white-list"))
		viper.BindPFlag("download.black-list", cmd.Flags().Lookup("black-list"))
		viper.BindPFlag("download.device", cmd.Flags().Lookup("device"))
		viper.BindPFlag("download.model", cmd.Flags().Lookup("model"))
		viper.BindPFlag("download.version", cmd.Flags().Lookup("version"))
		viper.BindPFlag("download.build", cmd.Flags().Lookup("build"))

		// settings
		proxy := viper.GetString("download.proxy")
		insecure := viper.GetBool("download.insecure")
		confirm := viper.GetBool("download.confirm")
		skipAll := viper.GetBool("download.skip-all")
		resumeAll := viper.GetBool("download.resume-all")
		restartAll := viper.GetBool("download.restart-all")
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
		getRSR := viper.GetBool("download.ota.rsr")
		remoteDyld := viper.GetBool("download.ota.dyld")
		dyldArches := viper.GetStringSlice("download.ota.dyld-arch")
		dyldDriverKit := viper.GetBool("download.ota.driver-kit")
		remoteKernel := viper.GetBool("download.ota.kernel")
		remotePattern := viper.GetString("download.ota.pattern")
		flat := viper.GetBool("download.ota.flat")
		otaInfo := viper.GetBool("download.ota.info")
		otaInfoType := viper.GetString("download.ota.info-type")
		output := viper.GetString("download.ota.output")
		// verify args
		if len(dyldArches) > 0 && !remoteDyld {
			return errors.New("--dyld-arch || -a can only be used with --dyld || -d")
		}
		if len(dyldArches) > 0 {
			for _, arch := range dyldArches {
				if !utils.StrSliceHas([]string{"arm64", "arm64e", "x86_64", "x86_64h"}, arch) {
					return fmt.Errorf("invalid dyld_shared_cache architecture '%s' (must be: arm64, arm64e, x86_64 or x86_64h)", arch)
				}
			}
		}
		if len(platform) == 0 || !utils.StrSliceHas([]string{"ios", "macos", "recovery", "watchos", "tvos", "audioos", "accessory"}, platform) {
			return fmt.Errorf("you must supply a valid --platform flag. Choices are: ios, watchos, tvos, audioos || accessory, macos, recovery")
		}
		if len(version) == 0 {
			version = "0"
		}
		if getRSR && len(build) == 0 {
			return fmt.Errorf("for now you will need to supply a --build number when using --rsr")
		}
		if len(build) == 0 {
			build = "0"
		}

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
					if !utils.StrSliceHas([]string{"iOS", "macOS"}, otaInfoType) {
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

		var destPath string
		if len(output) > 0 {
			destPath = filepath.Clean(output)
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
			RSR:             getRSR,
			Device:          device,
			Model:           model,
			Version:         ver,
			Build:           build,
			DeviceWhiteList: doDownload,
			DeviceBlackList: doNotDownload,
			Proxy:           proxy,
			Insecure:        insecure,
			TimeoutSeconds:  90,
		})
		if err != nil {
			return fmt.Errorf("failed to parse remote OTA XML: %v", err)
		}

		otas, err := otaXML.GetPallasOTAs()
		if err != nil {
			return err
		}

		if viper.GetBool("download.ota.urls") || viper.GetBool("download.ota.json") {
			if viper.GetBool("download.ota.json") {
				dat, err := json.Marshal(otas)
				if err != nil {
					return fmt.Errorf("failed to marshal OTA URLs in JSON: %v", err)
				}
				fmt.Println(string(dat))
			} else {
				for _, o := range otas {
					fmt.Println(o.BaseURL + o.RelativePath)
				}
			}
			return nil
		}

		if viper.GetBool("verbose") {
			log.Info("OTA(s):")
			for _, o := range otas {
				utils.Indent(log.WithFields(log.Fields{
					"name":         o.DocumentationID,
					"version":      o.OSVersion,
					"build":        o.Build,
					"device_count": len(o.SupportedDevices),
					"model_count":  len(o.SupportedDeviceModels),
					"size":         humanize.Bytes(uint64(o.UnarchivedSize)),
				}).Info, 2)(filepath.Base(o.RelativePath))
			}
		}

		log.Debug("URLs to Download:")
		for _, o := range otas {
			utils.Indent(log.Debug, 2)(o.BaseURL + o.RelativePath)
		}

		cont := true
		if !confirm {
			// if filtered to a single device skip the prompt
			if len(otas) > 1 {
				cont = false
				prompt := &survey.Confirm{
					Message: fmt.Sprintf("You are about to download %d OTA files. Continue?", len(otas)),
				}
				survey.AskOne(prompt, &cont)
			}
		}

		if cont {
			if remoteDyld || remoteKernel || len(remotePattern) > 0 {
				for _, o := range otas {
					log.WithFields(log.Fields{
						"version": o.OSVersion,
						"build":   o.Build,
						"devices": fmt.Sprintf("%s... (count=%d)", strings.Join(o.SupportedDevices[:3], " "), len(o.SupportedDevices)),
						"model":   strings.Join(o.SupportedDeviceModels, " "),
					}).Info(fmt.Sprintf("Getting %s remote OTA", o.DocumentationID))
					zr, err := download.NewRemoteZipReader(o.BaseURL+o.RelativePath, &download.RemoteConfig{
						Proxy:    proxy,
						Insecure: insecure,
					})
					if err != nil {
						return fmt.Errorf("failed to open remote zip to OTA: %v", err)
					}
					if remoteKernel { // REMOTE KERNEL MODE
						log.Info("Extracting remote kernelcache")
						err = kernelcache.RemoteParse(zr, destPath)
						if err != nil {
							return fmt.Errorf("failed to download kernelcache from remote ota: %v", err)
						}
					}
					if remoteDyld { // REMOTE DSC MODE
						found := false
						if runtime.GOOS == "darwin" { // FIXME: figure out how to do this on all platforms
							log.Info("Extracting remote dyld_shared_cache")
							if err := dyld.ExtractFromRemoteCryptex(zr, destPath, dyldArches); err != nil {
								log.Errorf("failed to download dyld_shared_cache from remote OTA: %v", err)
							}
							found = true
						}
						if !found {
							var dscRegex string
							if dyldDriverKit {
								dscRegex = fmt.Sprintf("%s(%s)%s", dyld.DriverKitCacheRegex, strings.Join(dyldArches, "|"), dyld.CacheRegexEnding)
							} else if utils.StrSliceHas([]string{"macos", "recovery"}, strings.ToLower(platform)) {
								dscRegex = fmt.Sprintf("%s(%s)%s", dyld.MacOSCacheRegex, strings.Join(dyldArches, "|"), dyld.CacheRegexEnding)
							} else {
								dscRegex = fmt.Sprintf("%s(%s)%s", dyld.IPhoneCacheRegex, strings.Join(dyldArches, "|"), dyld.CacheRegexEnding)
							}
							// hack: to get a priori list of files to extract (so we know when to stop)
							rfiles, err := ota.RemoteList(zr)
							if err != nil {
								return fmt.Errorf("failed to list remote OTA files: %v", err)
							}

							var matches []string
							for _, rf := range rfiles {
								if regexp.MustCompile(dscRegex).MatchString(rf.Name()) {
									matches = append(matches, rf.Name())
								}
							}

							log.Info("Extracting remote dyld_shared_cache(s) (can be a bit CPU intensive)")
							err = ota.RemoteExtract(zr, dscRegex, destPath, func(path string) bool {
								for i, v := range matches {
									if strings.HasSuffix(v, filepath.Base(path)) {
										matches = append(matches[:i], matches[i+1:]...)
									}
								}
								return len(matches) == 0 // stop if we've extracted all matches
							})
							if err != nil {
								return fmt.Errorf("failed to download dyld_shared_cache(s) from remote OTA: %v", err)
							}
						}
					}
					if len(remotePattern) > 0 { // REMOTE PATTERN MATCHING MODE
						log.Infof("Downloading files matching pattern %#v", remotePattern)
						iinfo, err := info.ParseZipFiles(zr.File)
						if err != nil {
							return errors.Wrap(err, "failed to parse remote ipsw")
						}
						folder, err := iinfo.GetFolder()
						if err != nil {
							log.Errorf("failed to get folder from remote ipsw metadata: %v", err)
						}
						if err := utils.RemoteUnzip(zr.File, regexp.MustCompile(remotePattern), filepath.Join(destPath, folder), flat); err != nil {
							utils.Indent(log.Warn, 2)("0 files matched pattern in remote OTA zip. Now checking payloadv2 payloads...")
							rfiles, err := ota.RemoteList(zr)
							if err != nil {
								return fmt.Errorf("failed to list remote OTA files: %v", err)
							}
							var matches []string
							for _, rf := range rfiles {
								if regexp.MustCompile(remotePattern).MatchString(rf.Name()) {
									matches = append(matches, rf.Name())
								}
							}
							if len(matches) == 0 {
								return fmt.Errorf("no files matched pattern %#v in remote OTA zip", remotePattern)
							}
							err = ota.RemoteExtract(zr, remotePattern, destPath, func(path string) bool {
								for i, v := range matches {
									if strings.HasSuffix(v, filepath.Base(path)) {
										matches = append(matches[:i], matches[i+1:]...)
									}
								}
								return len(matches) == 0 // stop if we've extracted all matches
							})
							if err != nil {
								return fmt.Errorf("failed to download dyld_shared_cache from remote ota: %v", err)
							}
						}
					}
				}
			} else {
				downloader := download.NewDownload(proxy, insecure, skipAll, resumeAll, restartAll, false, viper.GetBool("verbose"))
				for _, o := range otas {
					folder := filepath.Join(destPath, fmt.Sprintf("%s%s_OTAs", o.ProductSystemName, strings.TrimPrefix(o.OSVersion, "9.9.")))
					os.MkdirAll(folder, 0750)
					var devices string
					if len(o.SupportedDevices) > 0 {
						devices = strings.Join(o.SupportedDevices, "_")
					} else {
						devices = strings.Join(o.SupportedDeviceModels, "_")
					}
					url := o.BaseURL + o.RelativePath
					destName := filepath.Join(folder, fmt.Sprintf("%s_%s", devices, getDestName(url, removeCommas)))
					if _, err := os.Stat(destName); os.IsNotExist(err) {
						log.WithFields(log.Fields{
							"device": strings.Join(o.SupportedDevices, " "),
							"model":  strings.Join(o.SupportedDeviceModels, " "),
							"build":  o.Build,
							"type":   o.DocumentationID,
						}).Info(fmt.Sprintf("Getting %s %s OTA", o.ProductSystemName, strings.TrimPrefix(o.OSVersion, "9.9.")))
						// download file
						downloader.URL = url
						downloader.DestName = destName
						if err := downloader.Do(); err != nil {
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
