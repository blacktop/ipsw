/*
Copyright © 2018-2025 blacktop

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
	"sort"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/commands/extract"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/colors"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/blacktop/ipsw/pkg/ota/types"
	"github.com/dustin/go-humanize"
	semver "github.com/hashicorp/go-version"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var otaDlCmdPlatforms = []string{
	"ios\tiOS",
	"watchos\twatchOS",
	"tvos\ttvOS",
	"audioos\tAudioOS",
	"accessory\tAccessory: Studio Display, etc.",
	"macos\tmacOS",
	"recovery\trecoveryOS",
	"visionos\tvisionOS",
}

func init() {
	DownloadCmd.AddCommand(downloadOtaCmd)
	// Download behavior flags
	downloadOtaCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	downloadOtaCmd.Flags().Bool("insecure", false, "do not verify ssl certs")
	downloadOtaCmd.Flags().BoolP("confirm", "y", false, "do not prompt user for confirmation")
	downloadOtaCmd.Flags().Bool("skip-all", false, "always skip resumable IPSWs")
	downloadOtaCmd.Flags().Bool("resume-all", false, "always resume resumable IPSWs")
	downloadOtaCmd.Flags().Bool("restart-all", false, "always restart resumable IPSWs")
	downloadOtaCmd.Flags().BoolP("remove-commas", "_", false, "replace commas in IPSW filename with underscores")
	// Filter flags
	downloadOtaCmd.Flags().StringArray("white-list", []string{}, "iOS device white list")
	downloadOtaCmd.Flags().StringArray("black-list", []string{}, "iOS device black list")
	downloadOtaCmd.Flags().StringP("device", "d", "", "iOS Device (i.e. iPhone11,2)")
	downloadOtaCmd.Flags().StringP("model", "m", "", "iOS Model (i.e. D321AP)")
	downloadOtaCmd.Flags().StringP("version", "v", "", "iOS Version (i.e. 12.3.1)")
	downloadOtaCmd.Flags().StringP("build", "b", "", "iOS BuildID (i.e. 16F203)")
	// OTA-specific flags
	downloadOtaCmd.Flags().String("platform", "", "Platform to download (ios, watchos, tvos, audioos || accessory, macos, recovery)")
	downloadOtaCmd.RegisterFlagCompletionFunc("platform", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return otaDlCmdPlatforms, cobra.ShellCompDirectiveDefault
	})
	downloadOtaCmd.Flags().Bool("beta", false, "Download Beta OTAs")
	downloadOtaCmd.Flags().Bool("latest", false, "Download latest OTAs")
	downloadOtaCmd.Flags().Bool("delta", false, "Download Delta OTAs")
	downloadOtaCmd.Flags().Bool("rsr", false, "Download Rapid Security Response OTAs")
	downloadOtaCmd.Flags().Bool("sim", false, "Download Simulator OTAs")
	downloadOtaCmd.Flags().BoolP("kernel", "k", false, "Extract kernelcache from remote OTA zip")
	downloadOtaCmd.Flags().Bool("dyld", false, "Extract dyld_shared_cache(s) from remote OTA zip")
	downloadOtaCmd.Flags().BoolP("urls", "u", false, "Dump URLs only")
	downloadOtaCmd.Flags().BoolP("json", "j", false, "Dump URLs as JSON only")
	downloadOtaCmd.Flags().StringArrayP("dyld-arch", "a", []string{}, "dyld_shared_cache architecture(s) to remote extract")
	downloadOtaCmd.RegisterFlagCompletionFunc("dyld-arch", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return dyld.DscArches, cobra.ShellCompDirectiveDefault
	})
	downloadOtaCmd.Flags().Bool("driver-kit", false, "Extract DriverKit dyld_shared_cache(s) from remote OTA zip")
	downloadOtaCmd.Flags().String("pattern", "", "Download remote files that match regex")
	downloadOtaCmd.Flags().BoolP("flat", "f", false, "Do NOT preserve directory structure when downloading with --pattern")
	downloadOtaCmd.Flags().Bool("fcs-keys", false, "Get AEA decryption keys as JSON database from OTA metadata")
	downloadOtaCmd.Flags().Bool("info", false, "Show all the latest OTAs available")
	downloadOtaCmd.Flags().StringP("output", "o", "", "Folder to download files to")
	downloadOtaCmd.MarkFlagDirname("output")
	downloadOtaCmd.Flags().Bool("show-latest-version", false, "Show latest iOS version")
	downloadOtaCmd.Flags().Bool("show-latest-build", false, "Show latest iOS build")
	downloadOtaCmd.MarkFlagsMutuallyExclusive("info", "beta", "latest")
	// Bind download behavior flags
	viper.BindPFlag("download.ota.proxy", downloadOtaCmd.Flags().Lookup("proxy"))
	viper.BindPFlag("download.ota.insecure", downloadOtaCmd.Flags().Lookup("insecure"))
	viper.BindPFlag("download.ota.confirm", downloadOtaCmd.Flags().Lookup("confirm"))
	viper.BindPFlag("download.ota.skip-all", downloadOtaCmd.Flags().Lookup("skip-all"))
	viper.BindPFlag("download.ota.resume-all", downloadOtaCmd.Flags().Lookup("resume-all"))
	viper.BindPFlag("download.ota.restart-all", downloadOtaCmd.Flags().Lookup("restart-all"))
	viper.BindPFlag("download.ota.remove-commas", downloadOtaCmd.Flags().Lookup("remove-commas"))
	// Bind filter flags
	viper.BindPFlag("download.ota.white-list", downloadOtaCmd.Flags().Lookup("white-list"))
	viper.BindPFlag("download.ota.black-list", downloadOtaCmd.Flags().Lookup("black-list"))
	viper.BindPFlag("download.ota.device", downloadOtaCmd.Flags().Lookup("device"))
	viper.BindPFlag("download.ota.model", downloadOtaCmd.Flags().Lookup("model"))
	viper.BindPFlag("download.ota.version", downloadOtaCmd.Flags().Lookup("version"))
	viper.BindPFlag("download.ota.build", downloadOtaCmd.Flags().Lookup("build"))
	// Bind OTA-specific flags
	viper.BindPFlag("download.ota.platform", downloadOtaCmd.Flags().Lookup("platform"))
	viper.BindPFlag("download.ota.beta", downloadOtaCmd.Flags().Lookup("beta"))
	viper.BindPFlag("download.ota.latest", downloadOtaCmd.Flags().Lookup("latest"))
	viper.BindPFlag("download.ota.delta", downloadOtaCmd.Flags().Lookup("delta"))
	viper.BindPFlag("download.ota.rsr", downloadOtaCmd.Flags().Lookup("rsr"))
	viper.BindPFlag("download.ota.sim", downloadOtaCmd.Flags().Lookup("sim"))
	viper.BindPFlag("download.ota.dyld", downloadOtaCmd.Flags().Lookup("dyld"))
	viper.BindPFlag("download.ota.urls", downloadOtaCmd.Flags().Lookup("urls"))
	viper.BindPFlag("download.ota.json", downloadOtaCmd.Flags().Lookup("json"))
	viper.BindPFlag("download.ota.dyld-arch", downloadOtaCmd.Flags().Lookup("dyld-arch"))
	viper.BindPFlag("download.ota.driver-kit", downloadOtaCmd.Flags().Lookup("driver-kit"))
	viper.BindPFlag("download.ota.kernel", downloadOtaCmd.Flags().Lookup("kernel"))
	viper.BindPFlag("download.ota.pattern", downloadOtaCmd.Flags().Lookup("pattern"))
	viper.BindPFlag("download.ota.flat", downloadOtaCmd.Flags().Lookup("flat"))
	viper.BindPFlag("download.ota.fcs-keys", downloadOtaCmd.Flags().Lookup("fcs-keys"))
	viper.BindPFlag("download.ota.info", downloadOtaCmd.Flags().Lookup("info"))
	viper.BindPFlag("download.ota.output", downloadOtaCmd.Flags().Lookup("output"))
	viper.BindPFlag("download.ota.show-latest-version", downloadOtaCmd.Flags().Lookup("show-latest-version"))
	viper.BindPFlag("download.ota.show-latest-build", downloadOtaCmd.Flags().Lookup("show-latest-build"))
}

// downloadOtaCmd represents the ota download command
var downloadOtaCmd = &cobra.Command{
	Use:     "ota [options]",
	Aliases: []string{"o"},
	Short:   "Download OTAs",
	Example: heredoc.Doc(`
		# Download the iOS 14.8.1 OTA for the iPhone10,1
		❯ ipsw download ota --platform ios --version 14.8.1 --device iPhone10,1

		# Get all the latest BETA iOS OTAs URLs as JSON
		❯ ipsw download ota --platform ios --beta --urls --json

		# Download latest tvOS OTA and extract kernelcache
		❯ ipsw download ota --platform tvos --latest --kernel

		# Download Xcode Simulator Runtime OTAs
		❯ ipsw download ota --platform ios --sim --build "22F77"

		# Get AEA decryption keys as JSON from latest iOS OTAs
		❯ ipsw download ota --platform ios --latest --fcs-keys
	`),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		var err error
		var ver *semver.Version

		// settings
		proxy := viper.GetString("download.ota.proxy")
		insecure := viper.GetBool("download.ota.insecure")
		confirm := viper.GetBool("download.ota.confirm")
		skipAll := viper.GetBool("download.ota.skip-all")
		resumeAll := viper.GetBool("download.ota.resume-all")
		restartAll := viper.GetBool("download.ota.restart-all")
		removeCommas := viper.GetBool("download.ota.remove-commas")
		// filters
		device := viper.GetString("download.ota.device")
		model := viper.GetString("download.ota.model")
		version := viper.GetString("download.ota.version")
		build := viper.GetString("download.ota.build")
		doDownload := viper.GetStringSlice("download.ota.white-list")
		doNotDownload := viper.GetStringSlice("download.ota.black-list")
		// flags
		platform := viper.GetString("download.ota.platform")
		getBeta := viper.GetBool("download.ota.beta")
		getLatest := viper.GetBool("download.ota.latest")
		getRSR := viper.GetBool("download.ota.rsr")
		getSim := viper.GetBool("download.ota.sim")
		remoteDyld := viper.GetBool("download.ota.dyld")
		dyldArches := viper.GetStringSlice("download.ota.dyld-arch")
		dyldDriverKit := viper.GetBool("download.ota.driver-kit")
		remoteKernel := viper.GetBool("download.ota.kernel")
		remotePattern := viper.GetString("download.ota.pattern")
		flat := viper.GetBool("download.ota.flat")
		fcsKeys := viper.GetBool("download.ota.fcs-keys")
		otaInfo := viper.GetBool("download.ota.info")
		output := viper.GetString("download.ota.output")
		showLatestVersion := viper.GetBool("download.ota.show-latest-version")
		showLatestBuild := viper.GetBool("download.ota.show-latest-build")
		// verify args
		if len(dyldArches) > 0 && !remoteDyld {
			return errors.New("--dyld-arch || -a can only be used with --dyld || -d")
		}
		if len(dyldArches) > 0 {
			for _, arch := range dyldArches {
				if !utils.StrSliceHas(dyld.DscArches, arch) {
					return fmt.Errorf("invalid --dyld-arch: '%s' (must be one of %s)",
						arch,
						strings.Join(dyld.DscArches, ", "))
				}
			}
		}
		if platform == "" {
			return fmt.Errorf("you must supply a valid --platform flag. Choices are: ios, watchos, tvos, audioos, visionos || accessory, macos, recovery")
		} else {
			if !utils.StrSliceHas([]string{"ios", "macos", "recovery", "watchos", "tvos", "audioos", "accessory", "visionos"}, platform) {
				return fmt.Errorf("valid --platform flag choices are: ios, watchos, tvos, audioos, visionos || accessory, macos, recovery")
			}
		}
		if (showLatestVersion || showLatestBuild) && device == "" {
			return fmt.Errorf("you must supply a --device when using --show-latest-version or --show-latest-build")
		}
		if version == "" {
			version = "0"
		}
		if getRSR && build == "" {
			return fmt.Errorf("for now you will need to supply a --build number when using --rsr")
		}
		if viper.GetBool("download.ota.delta") && (build == "" || version == "") {
			return fmt.Errorf("for now you will need to supply a --version AND --build number when using --delta")
		}
		if build == "" {
			build = "0"
		}

		// Query for asset sets
		as, err := download.GetAssetSets(proxy, insecure)
		if err != nil {
			return err
		}

		/****************
		 * GET OTA INFO *
		 ****************/
		if otaInfo {
			if getSim {
				dvt, err := download.GetDVTDownloadableIndex()
				if err != nil {
					return err
				}
				for _, dl := range dvt.Downloadables {
					fmt.Printf("%-40s %s=%s\t%s=%s\n",
						dl.Name,
						colors.BoldHiBlue().Sprint("build"),
						dl.SimulatorVersion.BuildUpdate,
						colors.BoldHiBlue().Sprint("size"),
						humanize.Bytes(uint64(dl.FileSize)),
					)
				}
				return nil
			}
			if len(device) > 0 {
				log.WithField("device", device).Info("OTAs")
				for _, asset := range as.ForDevice(device) {
					utils.Indent(log.WithFields(log.Fields{
						"posting_date":    asset.PostingDate,
						"expiration_date": asset.ExpirationDate,
					}).Info, 2)(asset.ProductVersion)
				}
			} else {
				var otaInfoType string
				if utils.StrSliceHas([]string{"ios", "watchos", "tvos", "audioos"}, platform) {
					otaInfoType = "iOS"
				} else if utils.StrSliceHas([]string{"macos", "recovery"}, platform) {
					otaInfoType = "macOS"
				} else if utils.StrSliceHas([]string{"visionos"}, platform) {
					otaInfoType = "xrOS"
				} else {
					log.Errorf("--info flag does not support platform '%s'", platform)
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
					for _, device := range asset.SupportedDevices {
						utils.Indent(log.Info, 3)(device)
					}
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
				return fmt.Errorf("failed to convert version into semver object")
			}
		}

		otaXML, err := download.NewOTA(as, download.OtaConf{
			Platform:        strings.ToLower(platform),
			Beta:            getBeta,
			Latest:          getLatest,
			Delta:           viper.GetBool("download.ota.delta"),
			RSR:             getRSR,
			Simulator:       getSim,
			Device:          device,
			Model:           model,
			Version:         ver,
			Build:           build,
			DeviceWhiteList: doDownload,
			DeviceBlackList: doNotDownload,
			Proxy:           proxy,
			Insecure:        insecure,
			Timeout:         90,
		})
		if err != nil {
			return fmt.Errorf("failed to parse remote OTA XML: %v", err)
		}

		otas, err := otaXML.GetPallasOTAs()
		if err != nil {
			return fmt.Errorf("failed to get Pallas OTAs: %v", err)
		}

		if showLatestVersion {
			if len(otas) > 0 {
				fmt.Println(strings.TrimPrefix(otas[0].OSVersion, "9.9."))
				return nil
			}
			return fmt.Errorf("no OTA found")
		} else if showLatestBuild {
			if len(otas) > 0 {
				fmt.Println(otas[0].Build)
				return nil
			}
			return fmt.Errorf("no OTA found")
		}

		if fcsKeys {
			var fcsKeyEntries []types.AEAKeyEntry
			for _, o := range otas {
				if len(o.ArchiveDecryptionKey) > 0 {
					url := o.BaseURL + o.RelativePath
					filename := filepath.Base(o.RelativePath)
					fcsKeyEntries = append(fcsKeyEntries, types.AEAKeyEntry{
						OS:              o.ProductSystemName,
						Version:         strings.TrimPrefix(o.OSVersion, "9.9."),
						Build:           o.Build,
						Devices:         o.SupportedDevices,
						Models:          o.SupportedDeviceModels,
						Key:             o.ArchiveDecryptionKey,
						DocumentationID: o.DocumentationID,
						URL:             url,
						Filename:        filename,
						Size:            uint64(o.UnarchivedSize),
					})
				}
			}
			if len(fcsKeyEntries) == 0 {
				log.Warn("No AEA encrypted OTAs found with decryption keys")
				return nil
			}

			outFile := filepath.Join(destPath, "ota_fcs_keys.json")

			// Read existing entries if file exists
			var existingEntries []types.AEAKeyEntry
			if data, err := os.ReadFile(outFile); err == nil {
				if err := json.Unmarshal(data, &existingEntries); err != nil {
					log.WithError(err).Warn("Failed to parse existing FCS keys JSON, will overwrite")
				}
			}

			// Merge new entries with existing, using filename as unique key
			entryMap := make(map[string]types.AEAKeyEntry)
			for _, entry := range existingEntries {
				entryMap[entry.Filename] = entry
			}
			// Track actually new entries
			newCount := 0
			updatedCount := 0
			for _, entry := range fcsKeyEntries {
				if _, exists := entryMap[entry.Filename]; exists {
					updatedCount++
				} else {
					newCount++
				}
				entryMap[entry.Filename] = entry
			}

			// Extract keys and sort them for deterministic iteration
			keys := make([]string, 0, len(entryMap))
			for k := range entryMap {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			// Build slice in sorted key order, then sort by version/build
			mergedEntries := make([]types.AEAKeyEntry, 0, len(entryMap))
			for _, k := range keys {
				mergedEntries = append(mergedEntries, entryMap[k])
			}
			sort.Slice(mergedEntries, func(i, j int) bool {
				if mergedEntries[i].Version != mergedEntries[j].Version {
					return mergedEntries[i].Version > mergedEntries[j].Version
				}
				return mergedEntries[i].Build > mergedEntries[j].Build
			})

			dat, err := json.MarshalIndent(mergedEntries, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal FCS keys to JSON: %v", err)
			}
			if err := os.WriteFile(outFile, dat, 0644); err != nil {
				return fmt.Errorf("failed to write FCS keys JSON: %v", err)
			}

			if newCount > 0 && updatedCount > 0 {
				log.Infof("Added %d new, updated %d existing entries in %s (total: %d)", newCount, updatedCount, outFile, len(mergedEntries))
			} else if newCount > 0 {
				log.Infof("Added %d new entries to %s (total: %d)", newCount, outFile, len(mergedEntries))
			} else if updatedCount > 0 {
				log.Infof("Updated %d existing entries in %s (total: %d)", updatedCount, outFile, len(mergedEntries))
			} else {
				log.Infof("No changes to %s (total: %d)", outFile, len(mergedEntries))
			}

			return nil
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
					"version":      or([]string{o.OSVersion, o.SimulatorVersion}),
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
				if err := survey.AskOne(prompt, &cont); err == terminal.InterruptErr {
					log.Warn("Exiting...")
					return nil
				}
			}
		}

		if cont {
			if remoteDyld || remoteKernel || len(remotePattern) > 0 {
				for _, o := range otas {
					fields := log.Fields{
						"version": o.OSVersion,
						"build":   o.Build,
						"devices": fmt.Sprintf("%s... (count=%d)", strings.Join(o.SupportedDevices, " "), len(o.SupportedDevices)),
						"model":   strings.Join(o.SupportedDeviceModels, " "),
					}
					if o.IsEncrypted || len(o.ArchiveDecryptionKey) > 0 {
						fields["encrypted"] = true
						fields["key"] = o.ArchiveDecryptionKey
					}
					log.WithFields(fields).Info(fmt.Sprintf("Getting %s remote OTA", o.DocumentationID))

					config := &extract.Config{
						URL:          o.BaseURL + o.RelativePath,
						Pattern:      remotePattern,
						Proxy:        proxy,
						Insecure:     insecure,
						Arches:       dyldArches,
						DriverKit:    dyldDriverKit,
						KernelDevice: device,
						Flatten:      flat,
						Progress:     true,
						Encrypted:    o.IsEncrypted,
						AEAKey:       o.ArchiveDecryptionKey,
						Output:       destPath,
					}

					// check if AEA encryption
					isAEA, err := extract.IsAEA(config)
					if err != nil {
						return err
					} else if isAEA {
						log.Warn("This OTA is AEA encrypted and is NOT supported for remote extraction (yet 🤞)")
						return nil
					}

					if remoteKernel {
						log.Info("Extracting remote kernelcache")
						out, err := extract.Kernelcache(config)
						if err != nil {
							return fmt.Errorf("failed to extract kernelcache: %v", err)
						}
						for fn := range out {
							utils.Indent(log.Info, 2)("Created " + fn)
						}
					}
					if len(remotePattern) > 0 {
						log.Infof("Downloading files matching pattern %#v", remotePattern)
						out, err := extract.Search(config)
						if err != nil {
							return err
						}
						for _, f := range out {
							utils.Indent(log.Info, 2)("Created " + f)
						}
					}
					if remoteDyld {
						log.Info("Extracting dyld_shared_cache")
						out, err := extract.DSC(config)
						if err != nil {
							return err
						}
						for _, f := range out {
							utils.Indent(log.Info, 2)("Created " + f)
						}
					}
				}
			} else {
				downloader := download.NewDownload(proxy, insecure, skipAll, resumeAll, restartAll, false, viper.GetBool("verbose"))
				for _, o := range otas {
					folder := filepath.Join(destPath, fmt.Sprintf("%s%s_OTAs", o.ProductSystemName, strings.TrimPrefix(o.OSVersion, "9.9.")))
					if getSim {
						folder = filepath.Join(destPath, fmt.Sprintf("%s_%s_Simulator_OTAs", strings.ToUpper(platform), o.SimulatorVersion))
					}
					if err := os.MkdirAll(folder, 0750); err != nil {
						return fmt.Errorf("failed to create folder %s: %v", folder, err)
					}
					var devices string
					if len(o.SupportedDevices) > 0 {
						sort.Strings(o.SupportedDevices)
						if len(o.SupportedDevices) > 5 {
							devices = fmt.Sprintf("%s_and_%d_others", o.SupportedDevices[0], len(o.SupportedDevices)-1)
						} else {
							devices = strings.Join(o.SupportedDevices, "_")
						}
					} else {
						sort.Strings(o.SupportedDeviceModels)
						if len(o.SupportedDeviceModels) > 5 {
							devices = fmt.Sprintf("%s_and_%d_others", o.SupportedDeviceModels[0], len(o.SupportedDeviceModels)-1)
						} else {
							devices = strings.Join(o.SupportedDeviceModels, "_")
						}
					}
					url := o.BaseURL + o.RelativePath
					var isRSR string
					if o.SplatOnly {
						isRSR = fmt.Sprintf("%s_%s_%s_RSR_", o.OSVersion, o.ProductVersionExtra, o.Build)
					}
					var isAEA string
					if o.IsEncrypted || len(o.ArchiveDecryptionKey) > 0 {
						filesafe := o.ArchiveDecryptionKey
						filesafe = strings.ReplaceAll(filesafe, "/", "_")
						filesafe = strings.ReplaceAll(filesafe, "+", "-")
						isAEA = "KEY_[" + filesafe + "]_"
					}
					destName := filepath.Join(folder, fmt.Sprintf("%s_%s%s%s", devices, isRSR, isAEA, getDestName(url, removeCommas)))
					if getSim {
						destName = filepath.Join(folder, fmt.Sprintf("simulator_%s%s", isAEA, getDestName(url, removeCommas)))
					}
					if _, err := os.Stat(destName); os.IsNotExist(err) {
						fields := log.Fields{
							"device": strings.Join(o.SupportedDevices, " "),
							"model":  strings.Join(o.SupportedDeviceModels, " "),
							"build":  o.Build,
							"type":   or([]string{o.DocumentationID, "simulator"}),
						}
						if o.IsEncrypted || len(o.ArchiveDecryptionKey) > 0 {
							fields["encrypted"] = true
							fields["key"] = o.ArchiveDecryptionKey
						}
						log.WithFields(fields).Info(fmt.Sprintf("Getting %s %s OTA", o.ProductSystemName, strings.TrimPrefix(o.OSVersion, "9.9.")))
						// download file
						downloader.URL = url
						downloader.DestName = destName
						if err := downloader.Do(); err != nil {
							return fmt.Errorf("failed to download file: %v", err)
						}
					} else if err != nil {
						return fmt.Errorf("failed to stat file %s: %v", destName, err)
					} else {
						log.Warnf("OTA already exists: %s", destName)
					}
				}
			}
		}

		return nil
	},
}

func or(values []string) string {
	for _, v := range values {
		if len(v) > 0 {
			return v
		}
	}
	return ""
}
