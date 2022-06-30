/*
Copyright © 2022 blacktop

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
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
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
	downloadCmd.AddCommand(wikiCmd)
	wikiCmd.Flags().Bool("kernel", false, "Extract kernelcache from remote IPSW")
	wikiCmd.Flags().String("pattern", "", "Download remote files that match (not regex)")
	wikiCmd.Flags().StringP("output", "o", "", "Folder to download files to")
	viper.BindPFlag("download.wiki.kernel", wikiCmd.Flags().Lookup("kernel"))
	viper.BindPFlag("download.wiki.pattern", wikiCmd.Flags().Lookup("pattern"))
	viper.BindPFlag("download.wiki.output", wikiCmd.Flags().Lookup("output"))
}

// wikiCmd represents the wiki command
var wikiCmd = &cobra.Command{
	Use:           "wiki",
	Short:         "Download old(er) IPSWs from theiphonewiki.com",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

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

		// verify args
		if kernel && len(pattern) > 0 {
			return fmt.Errorf("you cannot supply a --kernel AND a --pattern (they are mutually exclusive)")
		}

		var destPath string
		if len(output) > 0 {
			destPath = filepath.Clean(output)
		}

		ipsws, err := download.ScrapeIPSWs()
		if err != nil {
			return fmt.Errorf("failed querying theiphonewiki.com: %v", err)
		}

		filteredURLS := download.FilterIpswURLs(ipsws, device, version, build)
		if len(filteredURLS) == 0 {
			log.Errorf("no ipsws match %s", strings.Join([]string{device, version, build}, ", "))
			return nil
		}

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
						return errors.Wrap(err, "failed to parse remote ipsw")
					}
					destPath = filepath.Join(destPath, iinfo.GetFolder())
					os.Mkdir(destPath, os.ModePerm)
					found := false
					for _, f := range zr.File {
						if strings.Contains(f.Name, pattern) {
							found = true
							fileName := filepath.Join(destPath, filepath.Base(filepath.Clean(f.Name)))
							if _, err := os.Stat(fileName); os.IsNotExist(err) {
								data := make([]byte, f.UncompressedSize64)
								rc, err := f.Open()
								if err != nil {
									return fmt.Errorf("failed to open file in zip: %v", err)
								}
								io.ReadFull(rc, data)
								rc.Close()
								utils.Indent(log.Info, 2)(fmt.Sprintf("Created %s", fileName))
								err = ioutil.WriteFile(fileName, data, 0660)
								if err != nil {
									return errors.Wrapf(err, "failed to write %s", f.Name)
								}
							} else {
								log.Warnf("%s already exists", fileName)
							}
						}
					}
					if !found {
						utils.Indent(log.Error, 2)(fmt.Sprintf("No files contain pattern %s", pattern))
					}
				}
			} else { // NORMAL MODE
				downloader := download.NewDownload(proxy, insecure, skipAll, resumeAll, restartAll, false, Verbose)
				for _, url := range filteredURLS {
					fname := filepath.Join(destPath, getDestName(url, removeCommas))
					if _, err := os.Stat(fname); os.IsNotExist(err) {
						d, v, b := download.ParseIpswURLString(url)
						log.WithFields(log.Fields{"devices": d, "build": b, "version": v}).Info("Getting IPSW")
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

		return nil
	},
}
