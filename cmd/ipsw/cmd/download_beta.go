/*
Copyright © 2019 blacktop

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

	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	downloadCmd.AddCommand(betaCmd)
}

// betaCmd represents the beta command
var betaCmd = &cobra.Command{
	Use:          "beta [build-id]",
	Short:        "Download beta IPSWs from theiphonewiki.com",
	Args:         cobra.MinimumNArgs(1),
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
		viper.BindPFlag("download.remove-commas", cmd.Flags().Lookup("remove-commas"))
		viper.BindPFlag("download.device", cmd.Flags().Lookup("device"))

		// settings
		proxy := viper.GetString("download.proxy")
		insecure := viper.GetBool("download.insecure")
		confirm := viper.GetBool("download.confirm")
		skipAll := viper.GetBool("download.skip-all")
		removeCommas := viper.GetBool("download.remove-commas")
		// filters
		device := viper.GetString("download.device")

		ipsws, err := download.ScrapeURLs(args[0])
		if err != nil {
			return errors.Wrap(err, "failed querying theiphonewiki.com")
		}

		var filteredURLS []string
		for url, ipsw := range ipsws {
			if len(device) > 0 {
				if utils.StrSliceContains(ipsw.Devices, device) {
					filteredURLS = append(filteredURLS, url)
				}
			} else {
				filteredURLS = append(filteredURLS, url)
			}
		}

		if len(filteredURLS) == 0 {
			log.Errorf("no ipsws match device %s", device)
			return nil
		}

		log.Debug("URLs to Download:")
		for _, url := range filteredURLS {
			utils.Indent(log.Debug, 2)(url)
		}

		cont := true
		if !confirm {
			cont = false
			prompt := &survey.Confirm{
				Message: fmt.Sprintf("You are about to download %d ipsw files. Continue?", len(filteredURLS)),
			}
			survey.AskOne(prompt, &cont)
		}

		if cont {
			downloader := download.NewDownload(proxy, insecure, skipAll, Verbose)
			for _, url := range filteredURLS {
				destName := getDestName(url, removeCommas)
				if _, err := os.Stat(destName); os.IsNotExist(err) {
					log.WithFields(log.Fields{
						"devices": ipsws[url].Devices,
						"build":   ipsws[url].BuildID,
						"version": ipsws[url].Version,
					}).Info("Getting IPSW")
					// download file
					downloader.URL = url
					downloader.DestName = destName

					err = downloader.Do()
					if err != nil {
						return errors.Wrap(err, "failed to download file")
					}
				} else {
					log.Warnf("ipsw already exists: %s", destName)
				}
			}
		}

		return nil
	},
}
