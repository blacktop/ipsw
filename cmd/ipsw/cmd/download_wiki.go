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
	"os"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	downloadCmd.AddCommand(wikiCmd)
}

// wikiCmd represents the wiki command
var wikiCmd = &cobra.Command{
	Use:          "wiki",
	Short:        "Download beta IPSWs from theiphonewiki.com",
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	Hidden:       true,
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
			// if filtered to a single device skip the prompt
			if len(filteredURLS) > 1 {
				cont = false
				prompt := &survey.Confirm{
					Message: fmt.Sprintf("You are about to download %d ipsw files. Continue?", len(filteredURLS)),
				}
				survey.AskOne(prompt, &cont)
			}
		}

		if cont {
			downloader := download.NewDownload(proxy, insecure, skipAll, resumeAll, restartAll, Verbose)
			for _, url := range filteredURLS {
				destName := getDestName(url, removeCommas)
				if _, err := os.Stat(destName); os.IsNotExist(err) {
					d, v, b := download.ParseIpswURLString(url)
					log.WithFields(log.Fields{"devices": d, "build": b, "version": v}).Info("Getting IPSW")
					// download file
					downloader.URL = url
					downloader.DestName = destName

					err = downloader.Do()
					if err != nil {
						return fmt.Errorf("failed to download IPSW: %v", err)
					}
				} else {
					log.Warnf("ipsw already exists: %s", destName)
				}
			}
		}

		return nil
	},
}
