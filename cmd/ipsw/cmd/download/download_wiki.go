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
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/commands/extract"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/plist"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DownloadCmd.AddCommand(wikiCmd)
	wikiCmd.Flags().Bool("ipsw", false, "Download IPSWs")
	wikiCmd.Flags().Bool("ota", false, "Download OTAs")
	wikiCmd.Flags().Bool("kernel", false, "Extract kernelcache from remote IPSW")
	wikiCmd.Flags().String("pattern", "", "Download remote files that match regex")
	wikiCmd.Flags().Bool("beta", false, "Download beta IPSWs/OTAs")
	wikiCmd.Flags().String("pv", "", "OTA prerequisite version")
	wikiCmd.Flags().String("pb", "", "OTA prerequisite build")
	wikiCmd.Flags().Bool("json", false, "Parse URLs and store metadata in local JSON database")
	wikiCmd.Flags().StringP("output", "o", "", "Folder to download files to")
	wikiCmd.Flags().String("db", "wiki_db.json", "Path to local JSON database (will use CWD by default)")
	wikiCmd.Flags().BoolP("flat", "f", false, "Do NOT perserve directory structure when downloading with --pattern")
	wikiCmd.SetHelpFunc(func(c *cobra.Command, s []string) {
		DownloadCmd.PersistentFlags().MarkHidden("white-list")
		DownloadCmd.PersistentFlags().MarkHidden("black-list")
		DownloadCmd.PersistentFlags().MarkHidden("model") // TODO: remove this?
		c.Parent().HelpFunc()(c, s)
	})
	viper.BindPFlag("download.wiki.ipsw", wikiCmd.Flags().Lookup("ipsw"))
	viper.BindPFlag("download.wiki.ota", wikiCmd.Flags().Lookup("ota"))
	viper.BindPFlag("download.wiki.kernel", wikiCmd.Flags().Lookup("kernel"))
	viper.BindPFlag("download.wiki.pattern", wikiCmd.Flags().Lookup("pattern"))
	viper.BindPFlag("download.wiki.beta", wikiCmd.Flags().Lookup("beta"))
	viper.BindPFlag("download.wiki.pv", wikiCmd.Flags().Lookup("pv"))
	viper.BindPFlag("download.wiki.pb", wikiCmd.Flags().Lookup("pb"))
	viper.BindPFlag("download.wiki.json", wikiCmd.Flags().Lookup("json"))
	viper.BindPFlag("download.wiki.output", wikiCmd.Flags().Lookup("output"))
	viper.BindPFlag("download.wiki.db", wikiCmd.Flags().Lookup("db"))
	viper.BindPFlag("download.wiki.flat", wikiCmd.Flags().Lookup("flat"))

	wikiCmd.MarkFlagsMutuallyExclusive("ipsw", "ota")
	wikiCmd.MarkFlagDirname("output")
}

// wikiCmd represents the wiki command
var wikiCmd = &cobra.Command{
	Use:           "wiki",
	Aliases:       []string{"w"},
	Short:         "Download old(er) IPSWs from theiphonewiki.com",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

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
		viper.BindPFlag("download.device", cmd.Flags().Lookup("device"))
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
		version := viper.GetString("download.version")
		build := viper.GetString("download.build")
		// flags
		dlIPSWs := viper.GetBool("download.wiki.ipsw")
		dlOTAs := viper.GetBool("download.wiki.ota")
		kernel := viper.GetBool("download.wiki.kernel")
		pattern := viper.GetString("download.wiki.pattern")
		output := viper.GetString("download.wiki.output")
		flat := viper.GetBool("download.wiki.flat")

		// validate flags
		if !dlIPSWs && !dlOTAs {
			return fmt.Errorf("must specify one of --ipsw or --ota")
		}
		if len(device) == 0 && len(version) == 0 && len(build) == 0 {
			return fmt.Errorf("must specify at least one of --device, --version, or --build")
		}
		if kernel && len(pattern) > 0 {
			return fmt.Errorf("cannot use --kernel and --pattern together")
		}

		var destPath string
		if len(output) > 0 {
			destPath = filepath.Clean(output)
		}

		if dlIPSWs { /* DOWNLOAD IPSWs */
			ipsws, err := download.GetWikiIPSWs(&download.WikiConfig{
				Device:  device,
				Version: version,
				Build:   build,
				IPSW:    dlIPSWs,
				OTA:     dlOTAs,
				Beta:    viper.GetBool("download.wiki.beta"),
			}, proxy, insecure)
			if err != nil {
				return fmt.Errorf("failed querying theiphonewiki.com: %v", err)
			}

			// ipsws, err := download.ScrapeIPSWs(viper.GetBool("download.wiki.beta"))
			// if err != nil {
			// 	return fmt.Errorf("failed querying theiphonewiki.com: %v", err)
			// }

			var filteredIPSW []download.WikiFirmware
			for _, ipsw := range ipsws {
				if len(version) > 0 || len(build) > 0 {
					if strings.HasPrefix(ipsw.Version, version) || strings.EqualFold(ipsw.Build, build) {
						if len(device) > 0 {
							for _, dev := range ipsw.Devices {
								if strings.EqualFold(dev, device) {
									if _, err := url.ParseRequestURI(ipsw.URL); err == nil {
										filteredIPSW = append(filteredIPSW, ipsw)
										break
									}
								}
							}
						} else {
							if _, err := url.ParseRequestURI(ipsw.URL); err == nil {
								filteredIPSW = append(filteredIPSW, ipsw)
							}
						}
					}
				} else {
					if len(device) > 0 {
						for _, dev := range ipsw.Devices {
							if strings.EqualFold(dev, device) {
								if _, err := url.ParseRequestURI(ipsw.URL); err == nil {
									filteredIPSW = append(filteredIPSW, ipsw)
									break
								}
							}
						}
					} else {
						if _, err := url.ParseRequestURI(ipsw.URL); err == nil {
							filteredIPSW = append(filteredIPSW, ipsw)
						}
					}
				}
			}

			if viper.GetBool("download.wiki.json") {
				db := make(map[string]*info.Info)
				if f, err := os.Open(viper.GetString("download.wiki.db")); err == nil { // try and load existing DB
					log.Info("Found existsing iphonewiki DB, loading...")
					defer f.Close()
					if err := json.NewDecoder(f).Decode(&db); err != nil {
						return fmt.Errorf("failed to decode JSON database: %v", err)
					}
					f.Close()
				}
				for idx, ipsw := range filteredIPSW {
					log.Debugf("Parsing IPSW %s", ipsw.URL)
					defer func() {
						// try and write out DB JSON on exit if possible
						dat, err := json.Marshal(db)
						if err != nil {
							log.Errorf("failed to marshal IPSW metadata: %v", err)
						}
						if err := os.WriteFile(viper.GetString("download.wiki.db"), dat, 0660); err != nil {
							log.Errorf("failed to write IPSW metadata: %v", err)
						}
					}()
					zr, err := download.NewRemoteZipReader(ipsw.URL, &download.RemoteConfig{
						Proxy:    proxy,
						Insecure: insecure,
					})
					if err != nil {
						log.Errorf("failed to create remote zip reader of ipsw: %v", err)
						db[ipsw.URL] = &info.Info{
							Plists: &plist.Plists{
								Type: "Dead IPSW",
							},
						}
						continue
					}
					i, err := info.ParseZipFiles(zr.File)
					if err != nil {
						log.Errorf("failed parsing remote IPSW URL: %v", err)
						continue
					}
					if i.Plists.BuildIdentities != nil && i.Plists.Restore != nil {
						log.WithFields(log.Fields{
							"devices": i.Plists.Restore.SupportedProductTypes,
							"build":   i.Plists.BuildManifest.ProductBuildVersion,
							"version": i.Plists.BuildManifest.ProductVersion,
						}).Infof("Parsing (%d/%d) IPSW", idx+1, len(filteredIPSW))
					}
					db[ipsw.URL] = i
				}
				dat, err := json.Marshal(db)
				if err != nil {
					return fmt.Errorf("failed to marshal IPSW metadata: %v", err)
				}
				if err := os.WriteFile(viper.GetString("download.wiki.db"), dat, 0660); err != nil {
					return fmt.Errorf("failed to write IPSW metadata: %v", err)
				}
			} else {
				log.Debug("URLs to download:")
				for _, ipsw := range filteredIPSW {
					utils.Indent(log.Debug, 2)(ipsw.URL)
				}

				cont := true
				if !confirm {
					if len(filteredIPSW) > 1 { // if filtered to a single device skip the prompt
						cont = false
						prompt := &survey.Confirm{
							Message: fmt.Sprintf("You are about to download %d IPSW files. Continue?", len(filteredIPSW)),
						}
						survey.AskOne(prompt, &cont)
					}
				}

				if cont {
					if kernel || len(pattern) > 0 {
						for _, ipsw := range filteredIPSW {
							d, v, b := download.ParseIpswURLString(ipsw.URL)
							log.WithFields(log.Fields{"devices": d, "build": b, "version": v}).Info("Parsing remote IPSW")

							config := &extract.Config{
								URL:          ipsw.URL,
								Pattern:      pattern,
								Proxy:        proxy,
								Insecure:     insecure,
								KernelDevice: device,
								Flatten:      flat,
								Progress:     true,
								Output:       destPath,
							}

							// REMOTE KERNEL MODE
							if kernel {
								log.Info("Extracting remote kernelcache")
								if _, err := extract.Kernelcache(config); err != nil {
									return fmt.Errorf("failed to extract kernelcache from remote IPSW: %v", err)
								}
							}
							// PATTERN MATCHING MODE
							if len(pattern) > 0 {
								log.Infof("Downloading files matching pattern %#v", pattern)
								if _, err := extract.Search(config); err != nil {
									return err
								}
							}
						}
					} else { // NORMAL MODE
						for _, ipsw := range filteredIPSW {
							destName := getDestName(ipsw.URL, removeCommas)
							if len(destPath) > 0 {
								destName = filepath.Join(filepath.Clean(destPath), destName)
							}
							if err := os.MkdirAll(filepath.Dir(destName), 0755); err != nil {
								return fmt.Errorf("failed to create directory: %v", err)
							}
							if _, err := os.Stat(destName); os.IsNotExist(err) {
								log.WithFields(log.Fields{
									"devices": ipsw.Devices,
									"build":   ipsw.Build,
									"version": fmt.Sprintf("%s%s", ipsw.Version, ipsw.VersionExtra),
								}).Info("Getting IPSW")

								downloader := download.NewDownload(proxy, insecure, skipAll, resumeAll, restartAll, false, viper.GetBool("verbose"))
								downloader.URL = ipsw.URL
								downloader.Sha1 = ipsw.Sha1Hash
								downloader.DestName = destName

								// append sha1 and filename to checksums file
								f, err := os.OpenFile("checksums.txt.sha1", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
								if err != nil {
									return fmt.Errorf("failed to open checksums.txt.sha1: %v", err)
								}
								defer f.Close()

								if _, err = f.WriteString(ipsw.Sha1Hash + "  " + destName + "\n"); err != nil {
									return fmt.Errorf("failed to write to checksums.txt.sha1: %v", err)
								}
							} else {
								log.Warnf("IPSW already exists: %s", destName)
							}
						}
					}
				}
			}
		} else { /* DOWNLOAD OTAs */
			otas, err := download.GetWikiOTAs(&download.WikiConfig{
				Device:  device,
				Version: version,
				Build:   build,
				IPSW:    dlIPSWs,
				OTA:     dlOTAs,
				Beta:    viper.GetBool("download.wiki.beta"),
			}, proxy, insecure)
			if err != nil {
				return fmt.Errorf("failed querying theiphonewiki.com: %v", err)
			}

			// otas, err := download.ScrapeOTAs(viper.GetBool("download.wiki.beta"))
			// if err != nil {
			// 	return fmt.Errorf("failed querying theiphonewiki.com: %v", err)
			// }

			uniqueAppend := func(slice []download.WikiFirmware, i download.WikiFirmware) []download.WikiFirmware {
				for _, ele := range slice {
					if ele.URL == i.URL {
						return slice
					}
				}
				return append(slice, i)
			}

			var filteredOTAs []download.WikiFirmware
			for _, ota := range otas {
				if len(version) > 0 || len(build) > 0 {
					if strings.HasPrefix(ota.Version, version) || strings.EqualFold(ota.Build, build) {
						log.Debugf("prerequisite version: %s, prerequisite build: %s", viper.GetString("download.wiki.pv"), viper.GetString("download.wiki.pb"))
						if !strings.EqualFold(ota.PrerequisiteVersion, viper.GetString("download.wiki.pv")) &&
							!strings.EqualFold(ota.Build, viper.GetString("download.wiki.pb")) {
							continue
						}
						if len(device) > 0 {
							for _, dev := range ota.Devices {
								if strings.EqualFold(dev, device) {
									if _, err := url.ParseRequestURI(ota.URL); err == nil {
										filteredOTAs = uniqueAppend(filteredOTAs, ota)
									}
								}
							}
						} else {
							if _, err := url.ParseRequestURI(ota.URL); err == nil {
								filteredOTAs = uniqueAppend(filteredOTAs, ota)
							}
						}
					}
				} else {
					if len(device) > 0 {
						for _, dev := range ota.Devices {
							if strings.EqualFold(dev, device) {
								if _, err := url.ParseRequestURI(ota.URL); err == nil {
									filteredOTAs = uniqueAppend(filteredOTAs, ota)
								}
							}
						}
					} else {
						if _, err := url.ParseRequestURI(ota.URL); err == nil {
							filteredOTAs = uniqueAppend(filteredOTAs, ota)
						}
					}
				}
			}

			if viper.GetBool("download.wiki.json") {
				db := make(map[string]info.InfoJSON)
				if f, err := os.Open(viper.GetString("download.wiki.db")); err == nil { // try and load existing DB
					log.Info("Found existsing iphonewiki DB, loading...")
					defer f.Close()
					if err := json.NewDecoder(f).Decode(&db); err != nil {
						return fmt.Errorf("failed to decode JSON database: %v", err)
					}
					f.Close()
				}
				defer func() {
					// try and write out DB JSON on exit if possible
					dat, err := json.Marshal(db)
					if err != nil {
						log.Errorf("failed to marshal OTA metadata: %v", err)
					}
					if err := os.WriteFile(viper.GetString("download.wiki.db"), dat, 0660); err != nil {
						log.Errorf("failed to write OTA metadata: %v", err)
					}
				}()
				for idx, ota := range otas {
					if _, ok := db[ota.URL]; !ok { // if NOT already in DB
						log.Debugf("Parsing OTA %s", ota.URL)
						zr, err := download.NewRemoteZipReader(ota.URL, &download.RemoteConfig{
							Proxy:    proxy,
							Insecure: insecure,
						})
						if err != nil {
							log.Errorf("failed to create remote zip reader of ipsw: %v", err)
							db[ota.URL] = info.InfoJSON{
								Type:  "DEAD OTA",
								Error: err.Error(),
							}
							continue
						}
						i, err := info.ParseZipFiles(zr.File)
						if err != nil {
							log.Errorf("failed parsing remote OTA URL: %v", err)
							continue
						}
						if i.Plists.BuildIdentities != nil {
							log.WithFields(log.Fields{
								"devices": i.Plists.MobileAssetProperties.SupportedDevices,
								"build":   i.Plists.BuildManifest.ProductBuildVersion,
								"version": i.Plists.BuildManifest.ProductVersion,
							}).Infof("Parsing (%d/%d) OTA", idx+1, len(otas))
						}
						// dat, err := json.Marshal(i)
						// if err != nil {
						// 	return fmt.Errorf("failed to marshal OTA metadata: %v", err)
						// }
						// if err := os.WriteFile(filepath.Join(destPath, fmt.Sprintf("ota_db_%d.json", idx)), dat, 0660); err != nil {
						// 	return fmt.Errorf("failed to write OTA metadata: %v", err)
						// }
						db[ota.URL] = i.ToJSON()
						dat, err := json.Marshal(db)
						if err != nil {
							return fmt.Errorf("failed to marshal OTA metadata: %v", err)
						}
						if err := os.WriteFile(viper.GetString("download.wiki.db"), dat, 0660); err != nil {
							return fmt.Errorf("failed to write OTA metadata: %v", err)
						}
					} else {
						log.Debugf("Skipping OTA (%d/%d) %s", idx, len(otas), ota.URL)
					}
				}
			} else {
				log.Debug("URLs to Download:")
				for _, o := range filteredOTAs {
					utils.Indent(log.Debug, 2)(o.URL)
				}

				cont := true
				if !confirm {
					// if filtered to a single device skip the prompt
					if len(filteredOTAs) > 1 {
						cont = false
						prompt := &survey.Confirm{
							Message: fmt.Sprintf("You are about to download %d OTA files. Continue?", len(filteredOTAs)),
						}
						survey.AskOne(prompt, &cont)
					}
				}

				if cont {
					if kernel || len(pattern) > 0 {
						for _, o := range filteredOTAs {
							var upto4 []string
							if len(o.Devices) > 4 {
								upto4 = o.Devices[:4]
							} else {
								upto4 = o.Devices
							}
							log.WithFields(log.Fields{
								"version": o.Version,
								"build":   o.Build,
								"devices": fmt.Sprintf("%s... (count=%d)", strings.Join(upto4, " "), len(o.Devices)),
								"model":   strings.Join(o.Devices, " "),
							}).Info("Getting remote OTA")

							config := &extract.Config{
								URL:          o.URL,
								Pattern:      pattern,
								Proxy:        proxy,
								Insecure:     insecure,
								KernelDevice: device,
								Flatten:      flat,
								Progress:     true,
								Output:       destPath,
							}

							// REMOTE KERNEL MODE
							if kernel {
								log.Info("Extracting remote kernelcache")
								if out, err := extract.Kernelcache(config); err != nil {
									return err
								} else {
									for fn := range out {
										utils.Indent(log.Info, 2)("Created " + fn)
									}
								}
							}
							// PATTERN MATCHING MODE
							if len(pattern) > 0 {
								log.Infof("Downloading files matching pattern %#v", pattern)
								if out, err := extract.Search(config); err != nil {
									return err
								} else {
									for _, f := range out {
										utils.Indent(log.Info, 2)("Created " + f)
									}
								}
							}
						}
					} else { // NORMAL MODE
						downloader := download.NewDownload(proxy, insecure, skipAll, resumeAll, restartAll, false, viper.GetBool("verbose"))
						for _, o := range filteredOTAs {
							folder := filepath.Join(destPath, fmt.Sprintf("%s%s_OTAs", o.Version, o.VersionExtra))
							os.MkdirAll(folder, 0750)
							var devices string
							if len(o.Devices) > 0 {
								sort.Strings(o.Devices)
								if len(o.Devices) > 5 {
									devices = fmt.Sprintf("%s_and_%d_others", o.Devices[0], len(o.Devices)-1)
								} else {
									devices = strings.Join(o.Devices, "_")
								}
							}
							url := o.URL
							destName := filepath.Join(folder, fmt.Sprintf("%s_%s", devices, getDestName(url, removeCommas)))
							if _, err := os.Stat(destName); os.IsNotExist(err) {
								log.WithFields(log.Fields{
									"device": strings.Join(o.Devices, " "),
									"model":  o.BoardID,
									"build":  o.Build,
								}).Info(fmt.Sprintf("Getting %s%s OTA", o.Version, o.VersionExtra))
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
			}
		}

		return nil
	},
}
