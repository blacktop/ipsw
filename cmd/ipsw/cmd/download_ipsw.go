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
package cmd

import (
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
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	downloadCmd.AddCommand(ipswCmd)

	ipswCmd.Flags().Bool("latest", false, "Download latest IPSWs")
	ipswCmd.Flags().Bool("show-latest", false, "Show latest iOS version")
	ipswCmd.Flags().Bool("macos", false, "Download macOS IPSWs")
	ipswCmd.Flags().Bool("ibridge", false, "Download iBridge IPSWs")
	ipswCmd.Flags().Bool("kernel", false, "Extract kernelcache from remote IPSW")
	// ipswCmd.Flags().BoolP("kernel-spec", "", false, "Download kernels into spec folders")
	ipswCmd.Flags().String("pattern", "", "Download remote files that match regex")
	ipswCmd.Flags().Bool("beta", false, "Download Beta IPSWs")
	ipswCmd.Flags().StringP("output", "o", "", "Folder to download files to")
	ipswCmd.Flags().BoolP("flat", "f", false, "Do NOT perserve directory structure when downloading with --pattern")
	viper.BindPFlag("download.ipsw.latest", ipswCmd.Flags().Lookup("latest"))
	viper.BindPFlag("download.ipsw.show-latest", ipswCmd.Flags().Lookup("show-latest"))
	viper.BindPFlag("download.ipsw.macos", ipswCmd.Flags().Lookup("macos"))
	viper.BindPFlag("download.ipsw.ibridge", ipswCmd.Flags().Lookup("ibridge"))
	viper.BindPFlag("download.ipsw.kernel", ipswCmd.Flags().Lookup("kernel"))
	// viper.BindPFlag("download.ipsw.kernel-spec", ipswCmd.Flags().Lookup("kernel-spec"))
	viper.BindPFlag("download.ipsw.pattern", ipswCmd.Flags().Lookup("pattern"))
	viper.BindPFlag("download.ipsw.beta", ipswCmd.Flags().Lookup("beta"))
	viper.BindPFlag("download.ipsw.output", ipswCmd.Flags().Lookup("output"))
	viper.BindPFlag("download.ipsw.flat", ipswCmd.Flags().Lookup("flat"))
}

// ipswCmd represents the ipsw command
var ipswCmd = &cobra.Command{
	Use:           "ipsw",
	Short:         "Download and parse IPSW(s) from the internets",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		var err error
		var ipsws []download.IPSW
		var itunes *download.ITunesVersionMaster
		var builds []download.Build
		var filteredBuilds []download.Build

		if Verbose {
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
		// model := viper.GetString("download.model")
		// version := viper.GetString("download.version")
		// build := viper.GetString("download.build")
		doDownload := viper.GetStringSlice("download.white-list")
		doNotDownload := viper.GetStringSlice("download.black-list")
		// flags
		latest := viper.GetBool("download.ipsw.latest")
		showLatest := viper.GetBool("download.ipsw.show-latest")
		macos := viper.GetBool("download.ipsw.macos")
		ibridge := viper.GetBool("download.ipsw.ibridge")
		kernel := viper.GetBool("download.ipsw.kernel")
		// kernelSpecFolders := viper.GetBool("download.ipsw.kernel-spec")
		pattern := viper.GetString("download.ipsw.pattern")
		output := viper.GetString("download.ipsw.output")
		flat := viper.GetBool("download.ipsw.flat")
		// beta := viper.GetBool("download.ipsw.beta")

		// verify args
		if kernel && len(pattern) > 0 {
			return fmt.Errorf("you cannot supply a --kernel AND a --pattern (they are mutually exclusive)")
		}

		var destPath string
		if len(output) > 0 {
			destPath = filepath.Clean(output)
		}

		if len(device) > 0 {
			db, err := info.GetIpswDB()
			if err != nil {
				return fmt.Errorf("failed to get ipsw device DB: %v", err)
			}
			if dev, err := db.LookupDevice(device); err == nil {
				if dev.SDKPlatform == "macosx" {
					macos = true
				}
			}
		}

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
		} else {
			if !showLatest { // This is a dumb hack to prevent having to pull down the FULL XML if you just want to know the latest iOS version
				itunes, err = download.NewiTunesVersionMaster()
				if err != nil {
					return fmt.Errorf("failed to create itunes API: %v", err)
				}
			}
		}

		if showLatest {
			if macos || ibridge {
				latestVersion, err := itunes.GetLatestVersion()
				if err != nil {
					return fmt.Errorf("failed to get latest iOS version: %v", err)
				}
				fmt.Print(latestVersion)
				// assets, err := download.GetAssetSets(proxy, insecure) // TODO: switch to this check (if IPSWs match eventually)
				// if err != nil {
				// 	return fmt.Errorf("failed to get latest iOS version: %v", err)
				// }
				// fmt.Print(assets.Latest("macOS"))
			} else {
				// latestVersion, err := itunes.GetLatestVersion()
				// if err != nil {
				// 	return fmt.Errorf("failed to get latest iOS version: %v", err)
				// }
				// fmt.Print(latestVersion)
				assets, err := download.GetAssetSets(proxy, insecure)
				if err != nil {
					return fmt.Errorf("failed to get latest iOS version: %v", err)
				}
				fmt.Print(assets.LatestVersion("iOS", "ios"))
			}
			return nil
		}

		if latest {
			builds, err = itunes.GetLatestBuilds(device)
			if err != nil {
				return fmt.Errorf("failed to get the latest builds: %v", err)
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
			ipsws, err = filterIPSWs(cmd)
			if err != nil {
				log.Fatal(err.Error())
			}
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
					Message: fmt.Sprintf("You are about to download %d ipsw files. Continue?", len(ipsws)),
				}
				survey.AskOne(prompt, &cont)
			}
		}

		if cont {
			if kernel { // REMOTE KERNEL MODE
				for _, i := range ipsws {
					log.WithFields(log.Fields{
						"device":  i.Identifier,
						"build":   i.BuildID,
						"version": i.Version,
						"signed":  i.Signed,
					}).Info("Parsing remote IPSW")

					log.Info("Extracting remote kernelcache")
					zr, err := download.NewRemoteZipReader(i.URL, &download.RemoteConfig{
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
				for _, i := range ipsws {
					log.WithFields(log.Fields{
						"device":  i.Identifier,
						"build":   i.BuildID,
						"version": i.Version,
						"signed":  i.Signed,
					}).Info("Parsing remote IPSW")
					dlRE, err := regexp.Compile(pattern)
					if err != nil {
						return errors.Wrap(err, "failed to compile regexp")
					}
					log.Infof("Downloading files matching pattern %#v", pattern)
					zr, err := download.NewRemoteZipReader(i.URL, &download.RemoteConfig{
						Proxy:    proxy,
						Insecure: insecure,
					})
					if err != nil {
						return fmt.Errorf("failed to create remote zip reader of ipsw: %v", err)
					}
					iinfo, err := info.ParseZipFiles(zr.File)
					if err != nil {
						return errors.Wrap(err, "failed to parse remote ipsw")
					}
					folder, err := iinfo.GetFolder()
					if err != nil {
						log.Errorf("failed to get folder from remote ipsw metadata: %v", err)
					}
					destPath = filepath.Join(destPath, folder)
					if err := utils.RemoteUnzip(zr.File, dlRE, destPath, flat); err != nil {
						return fmt.Errorf("failed to download pattern matching files from remote ipsw: %v", err)
					}
				}
			} else { // NORMAL MODE
				for _, i := range ipsws {
					destName := getDestName(i.URL, removeCommas)
					if _, err := os.Stat(destName); os.IsNotExist(err) {
						log.WithFields(log.Fields{
							"device":  i.Identifier,
							"build":   i.BuildID,
							"version": i.Version,
							"signed":  i.Signed,
						}).Info("Getting IPSW")

						downloader := download.NewDownload(proxy, insecure, skipAll, resumeAll, restartAll, false, Verbose)
						downloader.URL = i.URL
						downloader.Sha1 = i.SHA1
						downloader.DestName = destName

						err = downloader.Do()
						if err != nil {
							return fmt.Errorf("failed to download file: %v", err)
						}

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
						log.Warnf("ipsw already exists: %s", destName)
					}
				}
			}
		}
		return nil
	},
}
