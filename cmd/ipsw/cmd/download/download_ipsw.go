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
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/commands/extract"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/fatih/color"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DownloadCmd.AddCommand(downloadIpswCmd)
	// Download behavior flags
	downloadIpswCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	downloadIpswCmd.Flags().Bool("insecure", false, "do not verify ssl certs")
	downloadIpswCmd.Flags().BoolP("confirm", "y", false, "do not prompt user for confirmation")
	downloadIpswCmd.Flags().Bool("skip-all", false, "always skip resumable IPSWs")
	downloadIpswCmd.Flags().Bool("resume-all", false, "always resume resumable IPSWs")
	downloadIpswCmd.Flags().Bool("restart-all", false, "always restart resumable IPSWs")
	downloadIpswCmd.Flags().BoolP("remove-commas", "_", false, "replace commas in IPSW filename with underscores")
	// Filter flags
	downloadIpswCmd.Flags().StringArray("white-list", []string{}, "iOS device white list")
	downloadIpswCmd.Flags().StringArray("black-list", []string{}, "iOS device black list")
	downloadIpswCmd.Flags().StringP("device", "d", "", "iOS Device (i.e. iPhone11,2)")
	downloadIpswCmd.Flags().StringP("model", "m", "", "iOS Model (i.e. D321AP)")
	downloadIpswCmd.Flags().StringP("version", "v", "", "iOS Version (i.e. 12.3.1)")
	downloadIpswCmd.Flags().StringP("build", "b", "", "iOS BuildID (i.e. 16F203)")
	// IPSW-specific flags
	downloadIpswCmd.Flags().Bool("latest", false, "Download latest IPSWs")
	downloadIpswCmd.Flags().Bool("show-latest-version", false, "Show latest iOS version")
	downloadIpswCmd.Flags().Bool("show-latest-build", false, "Show latest iOS build")
	downloadIpswCmd.Flags().Bool("macos", false, "Download macOS IPSWs")
	downloadIpswCmd.Flags().Bool("ibridge", false, "Download iBridge IPSWs")
	downloadIpswCmd.Flags().Bool("kernel", false, "Extract kernelcache from remote IPSW")
	downloadIpswCmd.Flags().Bool("dyld", false, "Extract dyld_shared_cache(s) from remote IPSW")
	downloadIpswCmd.Flags().StringArrayP("dyld-arch", "a", []string{}, "dyld_shared_cache architecture(s) to remote extract")
	downloadIpswCmd.RegisterFlagCompletionFunc("dyld-arch", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return dyld.DscArches, cobra.ShellCompDirectiveDefault
	})
	// downloadIpswCmd.Flags().BoolP("kernel-spec", "", false, "Download kernels into spec folders")
	downloadIpswCmd.Flags().String("pattern", "", "Download remote files that match regex")
	downloadIpswCmd.Flags().Bool("fcs-keys", false, "Download AEA1 DMG fcs-key pem files")
	downloadIpswCmd.Flags().Bool("fcs-keys-json", false, "Download AEA1 DMG fcs-keys as JSON")
	downloadIpswCmd.Flags().Bool("decrypt", false, "Attempt to decrypt the partial files if keys are available")
	downloadIpswCmd.Flags().BoolP("flat", "f", false, "Do NOT perserve directory structure when downloading with --pattern")
	downloadIpswCmd.Flags().BoolP("urls", "u", false, "Dump URLs only")
	downloadIpswCmd.Flags().Bool("usb", false, "Download IPSWs for USB attached iDevices")
	downloadIpswCmd.Flags().StringP("output", "o", "", "Folder to download files to")
	downloadIpswCmd.MarkFlagDirname("output")
	// Bind download behavior flags
	viper.BindPFlag("download.ipsw.proxy", downloadIpswCmd.Flags().Lookup("proxy"))
	viper.BindPFlag("download.ipsw.insecure", downloadIpswCmd.Flags().Lookup("insecure"))
	viper.BindPFlag("download.ipsw.confirm", downloadIpswCmd.Flags().Lookup("confirm"))
	viper.BindPFlag("download.ipsw.skip-all", downloadIpswCmd.Flags().Lookup("skip-all"))
	viper.BindPFlag("download.ipsw.resume-all", downloadIpswCmd.Flags().Lookup("resume-all"))
	viper.BindPFlag("download.ipsw.restart-all", downloadIpswCmd.Flags().Lookup("restart-all"))
	viper.BindPFlag("download.ipsw.remove-commas", downloadIpswCmd.Flags().Lookup("remove-commas"))
	// Bind filter flags
	viper.BindPFlag("download.ipsw.white-list", downloadIpswCmd.Flags().Lookup("white-list"))
	viper.BindPFlag("download.ipsw.black-list", downloadIpswCmd.Flags().Lookup("black-list"))
	viper.BindPFlag("download.ipsw.device", downloadIpswCmd.Flags().Lookup("device"))
	viper.BindPFlag("download.ipsw.model", downloadIpswCmd.Flags().Lookup("model"))
	viper.BindPFlag("download.ipsw.version", downloadIpswCmd.Flags().Lookup("version"))
	viper.BindPFlag("download.ipsw.build", downloadIpswCmd.Flags().Lookup("build"))
	// Bind IPSW-specific flags
	viper.BindPFlag("download.ipsw.latest", downloadIpswCmd.Flags().Lookup("latest"))
	viper.BindPFlag("download.ipsw.show-latest-version", downloadIpswCmd.Flags().Lookup("show-latest-version"))
	viper.BindPFlag("download.ipsw.show-latest-build", downloadIpswCmd.Flags().Lookup("show-latest-build"))
	viper.BindPFlag("download.ipsw.macos", downloadIpswCmd.Flags().Lookup("macos"))
	viper.BindPFlag("download.ipsw.ibridge", downloadIpswCmd.Flags().Lookup("ibridge"))
	viper.BindPFlag("download.ipsw.kernel", downloadIpswCmd.Flags().Lookup("kernel"))
	viper.BindPFlag("download.ipsw.dyld", downloadIpswCmd.Flags().Lookup("dyld"))
	viper.BindPFlag("download.ipsw.dyld-arch", downloadIpswCmd.Flags().Lookup("dyld-arch"))
	// viper.BindPFlag("download.ipsw.kernel-spec", downloadIpswCmd.Flags().Lookup("kernel-spec"))
	viper.BindPFlag("download.ipsw.pattern", downloadIpswCmd.Flags().Lookup("pattern"))
	viper.BindPFlag("download.ipsw.fcs-keys", downloadIpswCmd.Flags().Lookup("fcs-keys"))
	viper.BindPFlag("download.ipsw.fcs-keys-json", downloadIpswCmd.Flags().Lookup("fcs-keys-json"))
	viper.BindPFlag("download.ipsw.decrypt", downloadIpswCmd.Flags().Lookup("decrypt"))
	viper.BindPFlag("download.ipsw.output", downloadIpswCmd.Flags().Lookup("output"))
	viper.BindPFlag("download.ipsw.flat", downloadIpswCmd.Flags().Lookup("flat"))
	viper.BindPFlag("download.ipsw.urls", downloadIpswCmd.Flags().Lookup("urls"))
	viper.BindPFlag("download.ipsw.usb", downloadIpswCmd.Flags().Lookup("usb"))
}

// downloadIpswCmd represents the ipsw command
var downloadIpswCmd = &cobra.Command{
	Use:     "ipsw",
	Aliases: []string{"i"},
	Short:   "Download and parse IPSW(s) from ipsw.me",
	Example: heredoc.Doc(`
		# Download latest iOS IPSWs for iPhone15,2
		❯ ipsw download ipsw --device iPhone15,2 --latest

		# Download specific iOS build with kernelcache extraction
		❯ ipsw download ipsw --device iPhone14,2 --build 20G75 --kernel

		# Get URLs only without downloading
		❯ ipsw download ipsw --device iPhone15,2 --version 17.0 --urls
	`),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		var err error
		var ipsws []download.IPSW
		var itunes *download.ITunesVersionMaster
		var builds []download.Build
		var filteredBuilds []download.Build

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// settings
		proxy := viper.GetString("download.ipsw.proxy")
		insecure := viper.GetBool("download.ipsw.insecure")
		confirm := viper.GetBool("download.ipsw.confirm")
		skipAll := viper.GetBool("download.ipsw.skip-all")
		resumeAll := viper.GetBool("download.ipsw.resume-all")
		restartAll := viper.GetBool("download.ipsw.restart-all")
		removeCommas := viper.GetBool("download.ipsw.remove-commas")
		// filters
		device := viper.GetString("download.ipsw.device")
		version := viper.GetString("download.ipsw.version")
		build := viper.GetString("download.ipsw.build")
		doDownload := viper.GetStringSlice("download.ipsw.white-list")
		doNotDownload := viper.GetStringSlice("download.ipsw.black-list")
		// flags
		latest := viper.GetBool("download.ipsw.latest")
		showLatestVersion := viper.GetBool("download.ipsw.show-latest-version")
		showLatestBuild := viper.GetBool("download.ipsw.show-latest-build")
		macos := viper.GetBool("download.ipsw.macos")
		ibridge := viper.GetBool("download.ipsw.ibridge")
		remoteKernel := viper.GetBool("download.ipsw.kernel")
		remoteDSC := viper.GetBool("download.ipsw.dyld")
		dyldArches := viper.GetStringSlice("download.ipsw.dyld-arch")
		// kernelSpecFolders := viper.GetBool("download.ipsw.kernel-spec")
		remotePattern := viper.GetString("download.ipsw.pattern")
		fcsKeys := viper.GetBool("download.ipsw.fcs-keys")
		fcsKeysJson := viper.GetBool("download.ipsw.fcs-keys-json")
		decrypt := viper.GetBool("download.ipsw.decrypt")
		output := viper.GetString("download.ipsw.output")
		flat := viper.GetBool("download.ipsw.flat")
		// verify args
		if len(device) == 0 && len(version) == 0 && len(build) == 0 && !latest && !showLatestVersion && !showLatestBuild && !viper.GetBool("download.ipsw.urls") {
			return fmt.Errorf("you must also supply a --device || --version || --build (or use --latest)")
		}
		if len(version) > 0 && len(build) > 0 {
			return fmt.Errorf("you cannot supply --version AND --build (they are mutually exclusive)")
		}
		if len(dyldArches) > 0 && !remoteDSC {
			return errors.New("--dyld-arch can only be used with --dyld")
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

		if viper.GetBool("download.ipsw.usb") {
			dev, err := utils.PickDevice()
			if err != nil {
				return err
			}
			device = dev.ProductType
			if !latest {
				build = dev.BuildVersion
			}
		}

		if len(device) > 0 {
			db, err := info.GetIpswDB()
			if err != nil {
				return fmt.Errorf("failed to get IPSW device DB: %v", err)
			}
			if dev, err := db.LookupDevice(device); err == nil {
				if dev.SDKPlatform == "macosx" {
					macos = true
				}
			}
		}

		if (showLatestVersion || showLatestBuild) && device == "" {
			if ibridge {
				itunes, err = download.NewIBridgeXML()
				if err != nil {
					return fmt.Errorf("failed to create itunes API: %v", err)
				}
				if showLatestVersion {
					latestVersion, err := itunes.GetLatestVersion()
					if err != nil {
						return fmt.Errorf("failed to get latest iBride version: %v", err)
					}
					fmt.Println(latestVersion)
				}
				if showLatestBuild {
					latestBuild, err := itunes.GetLatestBuild()
					if err != nil {
						return fmt.Errorf("failed to get latest iBride build: %v", err)
					}
					fmt.Println(latestBuild)
				}
			} else {
				assets, err := download.GetAssetSets(proxy, insecure)
				if err != nil {
					return fmt.Errorf("failed to get asset latest version: %v", err)
				}
				if macos {
					if showLatestVersion {
						fmt.Println(assets.LatestVersion("macos"))
					}
					if showLatestBuild {
						fmt.Println(assets.LatestBuild("macos"))
					}
				} else { // iOS
					if showLatestVersion {
						fmt.Println(assets.LatestVersion("ios"))
					}
					if showLatestBuild {
						fmt.Println(assets.LatestBuild("ios"))
					}
				}
			}
			return nil
		} else {
			if macos {
				itunes, err = download.NewMacOsXML()
				if err != nil {
					return fmt.Errorf("failed to create itunes API: %v", err)
				}
			} else if ibridge {
				itunes, err = download.NewIBridgeXML()
				if err != nil {
					return fmt.Errorf("failed to create itunes API: %v", err)
				}
			} else { // iOS
				itunes, err = download.NewiTunesVersionMaster()
				if err != nil {
					return fmt.Errorf("failed to create itunes API: %v", err)
				}
			}
			if showLatestVersion || showLatestBuild {
				builds, err = itunes.GetLatestBuilds(device)
				if err != nil {
					return fmt.Errorf("failed to get the latest builds: %v", err)
				}
				if len(builds) == 0 {
					return fmt.Errorf("no builds found for device: %s", device)
				}
				if showLatestVersion {
					fmt.Println(builds[0].Version)
				}
				if showLatestBuild {
					fmt.Println(builds[0].BuildID)
				}
				return nil
			}
		}

		if latest {
			builds, err = itunes.GetLatestBuilds(device)
			if err != nil {
				return fmt.Errorf("failed to get the latest builds: %v", err)
			}
			if len(builds) > 0 {
				utils.Indent(log.Info, 1)(fmt.Sprintf("Latest release found is: %s", builds[0].Version))
			}

			for _, v := range builds {
				if len(doDownload) > 0 {
					if utils.StrSliceHas(doDownload, v.Identifier) {
						filteredBuilds = append(filteredBuilds, v)
					}
				} else if len(doNotDownload) > 0 {
					if !utils.StrSliceHas(doNotDownload, v.Identifier) {
						filteredBuilds = append(filteredBuilds, v)
					}
				} else {
					filteredBuilds = append(filteredBuilds, v)
				}
			}

			if len(filteredBuilds) == 0 {
				return fmt.Errorf("no IPSWs match device(s) %s %s", device, strings.Join(doDownload, " "))
			}

			// convert from itunes to ipsw
			for _, b := range filteredBuilds {
				ipsws = append(ipsws, download.IPSW{
					Identifier: b.Identifier,
					Version:    b.Version,
					BuildID:    b.BuildID,
					SHA1:       b.FirmwareSHA1,
					URL:        b.URL,
					Signed:     true,
				})
			}
		} else {
			// Filter IPSWs based on provided criteria
			if len(version) > 0 {
				ipsws, err = download.GetAllIPSW(version)
				if err != nil {
					return fmt.Errorf("failed to query ipsw.me api for ALL ipsws for version %s: %v", version, err)
				}
			} else if len(build) > 0 {
				version, err = download.GetVersion(build)
				if err != nil {
					return fmt.Errorf("failed to query ipsw.me api for buildID %s => version: %v", build, err)
				}
				ipsws, err = download.GetAllIPSW(version)
				if err != nil {
					return fmt.Errorf("failed to query ipsw.me api for ALL ipsws for version %s: %v", version, err)
				}
				var buildFiltered []download.IPSW
				for _, i := range ipsws {
					if strings.EqualFold(build, i.BuildID) {
						buildFiltered = append(buildFiltered, i)
					}
				}
				ipsws = buildFiltered
			} else if len(device) > 0 {
				ipsws, err = download.GetDeviceIPSWs(device)
				if err != nil {
					return fmt.Errorf("failed to query ipsw.me api for device %s: %v", device, err)
				}
			}

			var filteredIPSWs []download.IPSW
			for _, i := range ipsws {
				if len(device) > 0 {
					if strings.EqualFold(device, i.Identifier) {
						filteredIPSWs = append(filteredIPSWs, i)
					}
				} else {
					if len(doDownload) > 0 {
						for _, doDown := range doDownload {
							if strings.HasPrefix(strings.ToLower(i.Identifier), strings.ToLower(doDown)) {
								filteredIPSWs = append(filteredIPSWs, i)
							}
						}
					} else if len(doNotDownload) > 0 {
						for _, dontDown := range doNotDownload {
							if !strings.HasPrefix(strings.ToLower(i.Identifier), strings.ToLower(dontDown)) {
								filteredIPSWs = append(filteredIPSWs, i)
							}
						}
					} else {
						filteredIPSWs = append(filteredIPSWs, i)
					}
				}
			}

			if macos {
				var furtherFilteredIPSWs []download.IPSW
				for _, i := range filteredIPSWs {
					if strings.Contains(i.Identifier, "Mac") {
						furtherFilteredIPSWs = append(furtherFilteredIPSWs, i)
					}
				}
				filteredIPSWs = furtherFilteredIPSWs
			}

			unique := make(map[string]bool, len(filteredIPSWs))
			var uniqueIPSWs []download.IPSW
			for _, i := range filteredIPSWs {
				if len(i.URL) != 0 {
					if !unique[i.URL] {
						uniqueIPSWs = append(uniqueIPSWs, i)
						unique[i.URL] = true
					}
				}
			}

			if len(uniqueIPSWs) == 0 {
				return fmt.Errorf("filter flags matched 0 IPSWs")
			}

			ipsws = uniqueIPSWs
		} // END IPSW FILTERING

		if viper.GetBool("download.ipsw.urls") {
			for _, i := range ipsws {
				fmt.Println(i.URL)
			}
			return nil
		}
		log.Debug("URLs to Download:")
		for _, i := range ipsws {
			utils.Indent(log.Debug, 2)(i.URL)
		}

		cont := true
		if !confirm {
			// if filtered to a single device skip the prompt
			if len(ipsws) > 1 {
				cont = false
				prompt := &survey.Confirm{
					Message: fmt.Sprintf("You are about to download %d IPSW files. Continue?", len(ipsws)),
				}
				if err := survey.AskOne(prompt, &cont); err != nil {
					if err == terminal.InterruptErr {
						log.Warn("Exiting...")
						return nil
					}
					return err
				}
			}
		}

		if cont {
			if remoteKernel || remoteDSC || len(remotePattern) > 0 {
				for _, ipsw := range ipsws {
					log.WithFields(log.Fields{
						"device":  ipsw.Identifier,
						"build":   ipsw.BuildID,
						"version": ipsw.Version,
						"signed":  ipsw.Signed,
					}).Info("Parsing remote IPSW")

					config := &extract.Config{
						IPSW:         "",
						URL:          ipsw.URL,
						Pattern:      remotePattern,
						Arches:       dyldArches,
						KernelDevice: device,
						Proxy:        proxy,
						Insecure:     insecure,
						DMGs:         false,
						DmgType:      "",
						Flatten:      flat,
						Progress:     true,
						Output:       output,
					}

					// REMOTE KERNEL MODE
					if remoteKernel {
						log.Info("Extracting remote kernelcache")
						if out, err := extract.Kernelcache(config); err != nil {
							return err
						} else {
							for fn := range out {
								utils.Indent(log.Info, 2)("Created " + fn)
							}
						}
					}
					// REMOTE DSC MODE
					if remoteDSC {
						log.Info("Extracting remote dyld_shared_cache(s)")
						if out, err := extract.DSC(config); err != nil {
							return err
						} else {
							for _, f := range out {
								utils.Indent(log.Info, 2)("Created " + f)
							}
						}
					}
					// REMOTE AEA1 DMG fcs-key MODE
					if fcsKeys || fcsKeysJson {
						if fcsKeysJson {
							config.JSON = true
						}
						log.Info("Extracting remote AEA1 DMG fcs-keys")
						if out, err := extract.FcsKeys(config); err != nil {
							return err
						} else {
							for _, f := range out {
								utils.Indent(log.Info, 2)("Created " + f)
							}
						}
					}
					// PATTERN MATCHING MODE
					if len(remotePattern) > 0 {
						log.Infof("Downloading files matching pattern %#v", remotePattern)
						if out, err := extract.Search(config); err != nil {
							return err
						} else {
							cwd, _ := os.Getwd()
							for _, f := range out {
								utils.Indent(log.Info, 2)("Created " + strings.TrimPrefix(f, cwd))
							}
							if decrypt {
								log.Info("Searching for keys to decrypt files")
								if keys, err := download.GetWikiFirmwareKeys(&download.WikiConfig{
									Keys:    true,
									Device:  ipsw.Identifier,
									Version: ipsw.Version,
									Build:   ipsw.BuildID,
								}, proxy, insecure); err == nil {
									for _, key := range keys {
										for idx, f := range key.Filename {
											var in string
											for _, o := range out {
												if strings.HasSuffix(strings.ToLower(o), strings.ToLower(strings.ReplaceAll(f, " ", "_"))) {
													in = o
													break
												}
											}
											if len(in) == 0 {
												continue // not found
											}
											if len(key.Key) > 0 && len(key.Key[idx]) > 0 && key.Key[idx] != "Unknown" &&
												len(key.Iv) > 0 && len(key.Iv[idx]) > 0 && key.Iv[idx] != "Unknown" {
												iv, err := hex.DecodeString(key.Iv[idx])
												if err != nil {
													return fmt.Errorf("failed to decode iv: %v", err)
												}
												k, err := hex.DecodeString(key.Key[idx])
												if err != nil {
													return fmt.Errorf("failed to decode key: %v", err)
												}
												utils.Indent(log.Info, 2)("Decrypted " + strings.TrimPrefix(in, cwd) + ".dec")
												if err := img4.DecryptPayload(in, in+".dec", iv, k); err != nil {
													return fmt.Errorf("failed to decrypt %s: %v", in, err)
												}
											} else if len(key.Kbag) > 0 && len(key.Kbag[idx]) > 0 && key.Kbag[idx] != "Unknown" {
												kbag, err := hex.DecodeString(key.Kbag[idx])
												if err != nil {
													return fmt.Errorf("failed to decode kbag: %v", err)
												}
												iv := kbag[:aes.BlockSize]
												key := kbag[aes.BlockSize:]
												utils.Indent(log.Info, 2)("Decrypted " + strings.TrimPrefix(in, cwd) + ".dec")
												if err := img4.DecryptPayload(in, in+".dec", iv, key); err != nil {
													return fmt.Errorf("failed to decrypt %s: %v", in, err)
												}
											}
										}
									}
								} else {
									return fmt.Errorf("failed to get decrypt files: %v", err)
								}
							}
						}
					}
				}
			} else { // NORMAL MODE
				for _, i := range ipsws {
					destName := getDestName(i.URL, removeCommas)
					if len(output) > 0 {
						destName = filepath.Join(filepath.Clean(output), destName)
					}
					if err := os.MkdirAll(filepath.Dir(destName), 0755); err != nil {
						return fmt.Errorf("failed to create directory: %v", err)
					}
					if _, err := os.Stat(destName); os.IsNotExist(err) {
						log.WithFields(log.Fields{
							"device":  i.Identifier,
							"build":   i.BuildID,
							"version": i.Version,
							"signed":  i.Signed,
						}).Info("Getting IPSW")

						downloader := download.NewDownload(proxy, insecure, skipAll, resumeAll, restartAll, false, viper.GetBool("verbose"))
						downloader.URL = i.URL
						downloader.Sha1 = i.SHA1
						downloader.DestName = destName

						if err := downloader.Do(); err != nil {
							return fmt.Errorf("failed to download file: %v", err)
						}

						log.Info("Created: " + destName)

						// append sha1 and filename to checksums file
						f, err := os.OpenFile("checksums.txt.sha1", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
						if err != nil {
							return fmt.Errorf("failed to open checksums.txt.sha1: %v", err)
						}
						defer f.Close()

						if _, err = f.WriteString(i.SHA1 + "  " + destName + "\n"); err != nil {
							return fmt.Errorf("failed to write to checksums.txt.sha1: %v", err)
						}
					} else {
						log.Warnf("IPSW already exists: %s", destName)
					}
				}
			}
		}

		return nil
	},
}
