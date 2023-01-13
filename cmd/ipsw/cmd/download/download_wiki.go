/*
Copyright © 2018-2023 blacktop

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
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/blacktop/ipsw/pkg/plist"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DownloadCmd.AddCommand(wikiCmd)
	wikiCmd.Flags().Bool("kernel", false, "Extract kernelcache from remote IPSW")
	wikiCmd.Flags().String("pattern", "", "Download remote files that match regex")
	wikiCmd.Flags().Bool("beta", false, "Download beta IPSWs/OTAs")
	wikiCmd.Flags().Bool("ota", false, "Download OTAs 🚧")
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
	viper.BindPFlag("download.wiki.kernel", wikiCmd.Flags().Lookup("kernel"))
	viper.BindPFlag("download.wiki.pattern", wikiCmd.Flags().Lookup("pattern"))
	viper.BindPFlag("download.wiki.beta", wikiCmd.Flags().Lookup("beta"))
	viper.BindPFlag("download.wiki.ota", wikiCmd.Flags().Lookup("ota"))
	viper.BindPFlag("download.wiki.json", wikiCmd.Flags().Lookup("json"))
	viper.BindPFlag("download.wiki.output", wikiCmd.Flags().Lookup("output"))
	viper.BindPFlag("download.wiki.db", wikiCmd.Flags().Lookup("db"))
	viper.BindPFlag("download.wiki.flat", wikiCmd.Flags().Lookup("flat"))
}

// wikiCmd represents the wiki command
var wikiCmd = &cobra.Command{
	Use:           "wiki",
	Short:         "Download old(er) IPSWs from theiphonewiki.com",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

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
		kernel := viper.GetBool("download.wiki.kernel")
		pattern := viper.GetString("download.wiki.pattern")
		output := viper.GetString("download.wiki.output")
		flat := viper.GetBool("download.wiki.flat")

		// verify args
		if kernel && len(pattern) > 0 {
			return fmt.Errorf("you cannot supply a --kernel AND a --pattern (they are mutually exclusive)")
		}

		var destPath string
		if len(output) > 0 {
			destPath = filepath.Clean(output)
		}

		if viper.GetBool("download.wiki.ota") { //OTAs
			otas, err := download.ScrapeOTAs(viper.GetBool("download.wiki.beta"))
			if err != nil {
				return fmt.Errorf("failed querying theiphonewiki.com: %v", err)
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
				for idx, url := range otas {
					if _, ok := db[url]; !ok { // if NOT already in DB
						log.Debugf("Parsing OTA %s", url)
						zr, err := download.NewRemoteZipReader(url, &download.RemoteConfig{
							Proxy:    proxy,
							Insecure: insecure,
						})
						if err != nil {
							log.Errorf("failed to create remote zip reader of ipsw: %v", err)
							db[url] = info.InfoJSON{
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
						log.WithFields(log.Fields{
							"devices": i.Plists.MobileAssetProperties.SupportedDevices,
							"build":   i.Plists.BuildManifest.ProductBuildVersion,
							"version": i.Plists.BuildManifest.ProductVersion,
						}).Infof("Parsing (%d/%d) OTA", idx+1, len(otas))
						// dat, err := json.Marshal(i)
						// if err != nil {
						// 	return fmt.Errorf("failed to marshal OTA metadata: %v", err)
						// }
						// if err := os.WriteFile(filepath.Join(destPath, fmt.Sprintf("ota_db_%d.json", idx)), dat, 0660); err != nil {
						// 	return fmt.Errorf("failed to write OTA metadata: %v", err)
						// }
						db[url] = i.ToJSON()
						dat, err := json.Marshal(db)
						if err != nil {
							return fmt.Errorf("failed to marshal OTA metadata: %v", err)
						}
						if err := os.WriteFile(viper.GetString("download.wiki.db"), dat, 0660); err != nil {
							return fmt.Errorf("failed to write OTA metadata: %v", err)
						}
					} else {
						log.Debugf("Skipping OTA (%d/%d) %s", idx, len(otas), url)
					}
				}
			} else {
				downloader := download.NewDownload(proxy, insecure, skipAll, resumeAll, restartAll, false, viper.GetBool("verbose"))
				for idx, url := range otas {
					fname := filepath.Join(destPath, getDestName(url, removeCommas))
					if _, err := os.Stat(fname); os.IsNotExist(err) {
						zr, err := download.NewRemoteZipReader(url, &download.RemoteConfig{
							Proxy:    proxy,
							Insecure: insecure,
						})
						if err != nil {
							return fmt.Errorf("failed to create remote zip reader of ipsw: %v", err)
						}
						i, err := info.ParseZipFiles(zr.File)
						if err != nil {
							return fmt.Errorf("failed parsing remote OTA URL: %v", err)
						}
						log.WithFields(log.Fields{
							"devices": i.Plists.MobileAssetProperties.SupportedDevices,
							"build":   i.Plists.BuildManifest.ProductBuildVersion,
							"version": i.Plists.BuildManifest.ProductVersion,
						}).Infof("Getting (%d/%d) OTA", idx+1, len(otas))
						// download file
						downloader.URL = url
						downloader.DestName = fname

						err = downloader.Do()
						if err != nil {
							return fmt.Errorf("failed to download OTA: %v", err)
						}
					} else {
						log.Warnf("OTA already exists: %s", fname)
					}
				}
			}
		} else { // IPSWs
			ipsws, err := download.ScrapeIPSWs(viper.GetBool("download.wiki.beta"))
			if err != nil {
				return fmt.Errorf("failed querying theiphonewiki.com: %v", err)
			}

			filteredURLS := download.FilterIpswURLs(ipsws, device, version, build)
			if len(filteredURLS) == 0 {
				log.Errorf("no ipsws match %s", strings.Join([]string{device, version, build}, ", "))
				return nil
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
				for idx, url := range filteredURLS {
					log.Debugf("Parsing IPSW %s", url)
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
					zr, err := download.NewRemoteZipReader(url, &download.RemoteConfig{
						Proxy:    proxy,
						Insecure: insecure,
					})
					if err != nil {
						log.Errorf("failed to create remote zip reader of ipsw: %v", err)
						db[url] = &info.Info{
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
					log.WithFields(log.Fields{
						"devices": i.Plists.Restore.SupportedProductTypes,
						"build":   i.Plists.BuildManifest.ProductBuildVersion,
						"version": i.Plists.BuildManifest.ProductVersion,
					}).Infof("Parsing (%d/%d) IPSW", idx+1, len(filteredURLS))
					db[url] = i
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
				for _, url := range filteredURLS {
					utils.Indent(log.Debug, 2)(url)
				}

				cont := true
				if !confirm {
					if len(filteredURLS) > 1 { // if filtered to a single device skip the prompt
						cont = false
						prompt := &survey.Confirm{
							Message: fmt.Sprintf("You are about to download %d ipsw files. Continue?", len(filteredURLS)),
						}
						survey.AskOne(prompt, &cont)
					}
				}

				if cont {
					if kernel { // REMOTE KERNEL MODE
						for _, url := range filteredURLS {
							d, v, b := download.ParseIpswURLString(url)
							log.WithFields(log.Fields{"devices": d, "build": b, "version": v}).Info("Parsing remote IPSW")
							log.Info("Extracting remote kernelcache")
							zr, err := download.NewRemoteZipReader(url, &download.RemoteConfig{
								Proxy:    proxy,
								Insecure: insecure,
							})
							if err != nil {
								return fmt.Errorf("failed to create remote zip reader of ipsw: %v", err)
							}
							if err := kernelcache.RemoteParse(zr, destPath); err != nil {
								return fmt.Errorf("failed to download kernelcache from remote ipsw: %v", err)
							}
						}
					} else if len(pattern) > 0 { // PATTERN MATCHING MODE
						dlRE, err := regexp.Compile(pattern)
						if err != nil {
							return fmt.Errorf("failed to compile regex: %v", err)
						}
						for _, url := range filteredURLS {
							d, v, b := download.ParseIpswURLString(url)
							log.WithFields(log.Fields{"devices": d, "build": b, "version": v}).Info("Parsing remote IPSW")
							log.Infof("Downloading files that contain: %s", pattern)
							zr, err := download.NewRemoteZipReader(url, &download.RemoteConfig{
								Proxy:    proxy,
								Insecure: insecure,
							})
							if err != nil {
								return fmt.Errorf("failed to create remote zip reader of ipsw: %v", err)
							}
							iinfo, err := info.ParseZipFiles(zr.File)
							if err != nil {
								return fmt.Errorf("failed to parse remote IPSW URL: %v", err)
							}
							folder, err := iinfo.GetFolder()
							if err != nil {
								log.Errorf("failed to get folder from remote ipsw: %v", err)
							}
							destPath = filepath.Join(destPath, folder)
							if err := utils.RemoteUnzip(zr.File, dlRE, destPath, flat); err != nil {
								return fmt.Errorf("failed to download pattern matching files from remote IPSW: %v", err)
							}
						}
					} else { // NORMAL MODE
						downloader := download.NewDownload(proxy, insecure, skipAll, resumeAll, restartAll, false, viper.GetBool("verbose"))
						for idx, url := range filteredURLS {
							fname := filepath.Join(destPath, getDestName(url, removeCommas))
							if _, err := os.Stat(fname); os.IsNotExist(err) {
								d, v, b := download.ParseIpswURLString(url)
								log.WithFields(log.Fields{"devices": d, "build": b, "version": v}).Infof("Getting (%d/%d) IPSW", idx+1, len(filteredURLS))
								// download file
								downloader.URL = url
								downloader.DestName = fname

								err = downloader.Do()
								if err != nil {
									return fmt.Errorf("failed to download IPSW: %v", err)
								}
							} else {
								log.Warnf("ipsw already exists: %s", fname)
							}
						}
					}
				}
			}
		}

		return nil
	},
}
