/*
Copyright © 2018-2024 blacktop

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
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/commands/extract"
	"github.com/blacktop/ipsw/internal/commands/img4"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/fatih/color"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DownloadCmd.AddCommand(ipswCmd)

	ipswCmd.Flags().Bool("latest", false, "Download latest IPSWs")
	ipswCmd.Flags().Bool("show-latest-version", false, "Show latest iOS version")
	ipswCmd.Flags().Bool("show-latest-build", false, "Show latest iOS build")
	ipswCmd.Flags().Bool("macos", false, "Download macOS IPSWs")
	ipswCmd.Flags().Bool("ibridge", false, "Download iBridge IPSWs")
	ipswCmd.Flags().Bool("kernel", false, "Extract kernelcache from remote IPSW")
	ipswCmd.Flags().Bool("dyld", false, "Extract dyld_shared_cache(s) from remote IPSW")
	ipswCmd.Flags().StringArrayP("dyld-arch", "a", []string{}, "dyld_shared_cache architecture(s) to remote extract")
	// ipswCmd.Flags().BoolP("kernel-spec", "", false, "Download kernels into spec folders")
	ipswCmd.Flags().String("pattern", "", "Download remote files that match regex")
	ipswCmd.Flags().Bool("decrypt", false, "Attempt to decrypt the partial files if keys are available")
	ipswCmd.Flags().StringP("output", "o", "", "Folder to download files to")
	ipswCmd.Flags().BoolP("flat", "f", false, "Do NOT perserve directory structure when downloading with --pattern")
	ipswCmd.Flags().BoolP("urls", "u", false, "Dump URLs only")
	ipswCmd.Flags().Bool("usb", false, "Download IPSWs for USB attached iDevices")
	ipswCmd.MarkFlagDirname("output")

	viper.BindPFlag("download.ipsw.latest", ipswCmd.Flags().Lookup("latest"))
	viper.BindPFlag("download.ipsw.show-latest-version", ipswCmd.Flags().Lookup("show-latest-version"))
	viper.BindPFlag("download.ipsw.show-latest-build", ipswCmd.Flags().Lookup("show-latest-build"))
	viper.BindPFlag("download.ipsw.macos", ipswCmd.Flags().Lookup("macos"))
	viper.BindPFlag("download.ipsw.ibridge", ipswCmd.Flags().Lookup("ibridge"))
	viper.BindPFlag("download.ipsw.kernel", ipswCmd.Flags().Lookup("kernel"))
	viper.BindPFlag("download.ipsw.dyld", ipswCmd.Flags().Lookup("dyld"))
	viper.BindPFlag("download.ipsw.dyld-arch", ipswCmd.Flags().Lookup("dyld-arch"))
	// viper.BindPFlag("download.ipsw.kernel-spec", ipswCmd.Flags().Lookup("kernel-spec"))
	viper.BindPFlag("download.ipsw.pattern", ipswCmd.Flags().Lookup("pattern"))
	viper.BindPFlag("download.ipsw.decrypt", ipswCmd.Flags().Lookup("decrypt"))
	viper.BindPFlag("download.ipsw.output", ipswCmd.Flags().Lookup("output"))
	viper.BindPFlag("download.ipsw.flat", ipswCmd.Flags().Lookup("flat"))
	viper.BindPFlag("download.ipsw.urls", ipswCmd.Flags().Lookup("urls"))
	viper.BindPFlag("download.ipsw.usb", ipswCmd.Flags().Lookup("usb"))
}

// ipswCmd represents the ipsw command
var ipswCmd = &cobra.Command{
	Use:           "ipsw",
	Aliases:       []string{"i"},
	Short:         "Download and parse IPSW(s) from the internets",
	SilenceUsage:  true,
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
		// model := viper.GetString("download.model")
		// version := viper.GetString("download.version")
		// build := viper.GetString("download.build")
		doDownload := viper.GetStringSlice("download.white-list")
		doNotDownload := viper.GetStringSlice("download.black-list")
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
		decrypt := viper.GetBool("download.ipsw.decrypt")
		output := viper.GetString("download.ipsw.output")
		flat := viper.GetBool("download.ipsw.flat")

		// verify args
		if len(dyldArches) > 0 && !remoteDSC {
			return errors.New("--dyld-arch can only be used with --dyld")
		}
		if len(dyldArches) > 0 {
			for _, arch := range dyldArches {
				if !utils.StrSliceHas([]string{"arm64", "arm64e", "x86_64", "x86_64h"}, arch) {
					return fmt.Errorf("invalid dyld_shared_cache architecture '%s' (must be: arm64, arm64e, x86_64 or x86_64h)", arch)
				}
			}
		}

		if viper.GetBool("download.ipsw.usb") {
			dev, err := utils.PickDevice()
			if err != nil {
				return err
			}
			dFlg.Device = dev.ProductType
			dFlg.Build = dev.BuildVersion
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

		if showLatestVersion || showLatestBuild {
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
				log.Fatal(fmt.Sprintf("no IPSWs match device(s) %s %s", device, strings.Join(doDownload, " ")))
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
			ipsws, err = filterIPSWs(cmd, macos)
			if err != nil {
				log.Fatal(err.Error())
			}
		}

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
				survey.AskOne(prompt, &cont)
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
													return fmt.Errorf("failed to decode --iv-key: %v", err)
												}
												k, err := hex.DecodeString(key.Key[idx])
												if err != nil {
													return fmt.Errorf("failed to decode --iv-key: %v", err)
												}
												utils.Indent(log.Info, 2)("Decrypted " + strings.TrimPrefix(in, cwd) + ".dec")
												if err := img4.DecryptPayload(in, in+".dec", iv, k); err != nil {
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
