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
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	downloadCmd.AddCommand(ipswCmd)

	ipswCmd.Flags().Bool("kernel", false, "Extract kernelcache from remote IPSW")
	viper.BindPFlag("download.ipsw.kernel", ipswCmd.Flags().Lookup("kernel"))
	ipswCmd.Flags().BoolP("kernel-spec", "", false, "Download kernels into spec folders")
	viper.BindPFlag("download.ipsw.kernel-spec", ipswCmd.Flags().Lookup("kernel-spec"))
	ipswCmd.Flags().Bool("pattern", false, "Download remote files that contain file name part")
	viper.BindPFlag("download.ipsw.pattern", ipswCmd.Flags().Lookup("pattern"))
	ipswCmd.Flags().Bool("macos", false, "Download macOS IPSWs")
	viper.BindPFlag("download.ipsw.macos", ipswCmd.Flags().Lookup("macos"))
	ipswCmd.Flags().Bool("latest", false, "Download latest IPSWs")
	viper.BindPFlag("download.ipsw.latest", ipswCmd.Flags().Lookup("latest"))
	ipswCmd.Flags().Bool("show-latest", false, "Show latest iOS version")
	viper.BindPFlag("download.ipsw.show-latest", ipswCmd.Flags().Lookup("show-latest"))
	ipswCmd.Flags().Bool("beta", false, "Download Beta IPSWs")
	viper.BindPFlag("download.ipsw.beta", ipswCmd.Flags().Lookup("beta"))
}

// ipswCmd represents the ipsw command
var ipswCmd = &cobra.Command{
	Use:          "ipsw",
	Short:        "Download and parse IPSW(s) from the internets",
	SilenceUsage: true,
	Hidden:       true,
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
		kernel := viper.GetBool("download.ipsw.kernel")
		kernelSpecFolders := viper.GetBool("download.ipsw.kernel-spec")
		// pattern := viper.GetBool("download.ipsw.pattern")
		macos := viper.GetBool("download.ipsw.macos")
		latest := viper.GetBool("download.ipsw.latest")
		showLatest := viper.GetBool("download.ipsw.show-latest")
		// beta := viper.GetBool("download.ipsw.beta")

		var destPath string
		if len(args) > 0 {
			destPath = filepath.Clean(args[0])
		}

		if macos {
			itunes, err = download.NewMacOsXML()
			if err != nil {
				return fmt.Errorf("failed to create itunes API: %v", err)
			}
		} else {
			itunes, err = download.NewiTunesVersionMaster()
			if err != nil {
				return fmt.Errorf("failed to create itunes API: %v", err)
			}
		}

		if showLatest {
			if macos {
				latestVersion, err := itunes.GetLatestVersion()
				if err != nil {
					return fmt.Errorf("failed to get latest iOS version: %v", err)
				}
				fmt.Print(latestVersion)
				// assets, err := download.GetAssetSets(proxy, insecure)
				// if err != nil {
				// 	return fmt.Errorf("failed to get latest iOS version: %v", err)
				// }
				// fmt.Print(assets.Latest("macOS"))
			} else {
				assets, err := download.GetAssetSets(proxy, insecure)
				if err != nil {
					return fmt.Errorf("failed to get latest iOS version: %v", err)
				}
				fmt.Print(assets.Latest("iOS"))
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
					if kernelSpecFolders {
						err = kernelcache.RemoteParse(zr, destPath)
					} else {
						err = kernelcache.RemoteParseV2(zr, filepath.Join(destPath, i.BuildID))
					}
					if err != nil {
						return fmt.Errorf("failed to download kernelcache from remote ipsw: %v", err)
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

						downloader := download.NewDownload(proxy, insecure, skipAll, resumeAll, restartAll, Verbose)
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
