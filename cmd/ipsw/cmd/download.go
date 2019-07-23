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
	"path"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/api"
	"github.com/blacktop/ipsw/utils"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(downloadCmd)

	// Persistent Flags which will work for this command and all subcommands
	downloadCmd.PersistentFlags().String("proxy", "", "HTTP/HTTPS proxy")
	downloadCmd.PersistentFlags().Bool("insecure", false, "do not verify ssl certs")
	// Filters
	downloadCmd.PersistentFlags().StringP("black-list", "n", viper.GetString("IPSW_DEVICE_BLACKLIST"), "iOS device black list")
	downloadCmd.PersistentFlags().StringP("version", "v", viper.GetString("IPSW_VERSION"), "iOS Version (i.e. 12.3.1)")
	downloadCmd.PersistentFlags().StringP("device", "d", viper.GetString("IPSW_DEVICE"), "iOS Device (i.e. iPhone11,2)")
	downloadCmd.PersistentFlags().StringP("build", "b", viper.GetString("IPSW_BUILD"), "iOS BuildID (i.e. 16F203)")
}

// LookupByURL searchs for a ipsw in an array by a download URL
func LookupByURL(ipsws []api.IPSW, dlURL string) (api.IPSW, error) {
	for _, i := range ipsws {
		if strings.EqualFold(dlURL, i.URL) {
			return i, nil
		}
	}
	return api.IPSW{}, fmt.Errorf("unable to find %s in ipsws", dlURL)
}

// downloadCmd represents the download command
var downloadCmd = &cobra.Command{
	Use:   "download",
	Short: "Download and parse IPSW(s) from the internets",
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		proxy, _ := cmd.Flags().GetString("proxy")
		insecure, _ := cmd.Flags().GetBool("insecure")

		// filters
		version, _ := cmd.Flags().GetString("version")
		device, _ := cmd.Flags().GetString("device")
		doNotDownload, _ := cmd.Flags().GetString("black-list")
		build, _ := cmd.Flags().GetString("build")

		if len(version) > 0 && len(build) > 0 {
			log.Fatal("you cannot supply a --version AND a --build (they are mutually exclusive)")
		}

		if len(version) > 0 {
			urls := []string{}
			ipsws, err := api.GetAllIPSW(version)
			if err != nil {
				return errors.Wrap(err, "failed to query ipsw.me api")
			}
			for _, i := range ipsws {
				if len(device) > 0 {
					if strings.EqualFold(device, i.Identifier) {
						urls = append(urls, i.URL)
					}
				} else {
					if len(doNotDownload) > 0 {
						if !strings.Contains(i.Identifier, doNotDownload) {
							urls = append(urls, i.URL)
						}
					} else {
						urls = append(urls, i.URL)
					}
				}
			}
			urls = utils.Unique(urls)

			log.Debug("URLs to Download:")
			for _, u := range urls {
				utils.Indent(log.Debug)(u)
			}

			cont := true
			// if filtered to a single device skip the prompt
			if len(device) == 0 {
				cont = false
				prompt := &survey.Confirm{
					Message: fmt.Sprintf("You are about to download %d ipsw files. Continue?", len(urls)),
				}
				survey.AskOne(prompt, &cont)
			}

			if cont {
				for _, url := range urls {
					if _, err := os.Stat(path.Base(url)); os.IsNotExist(err) {
						// get a handle to ipsw object
						i, err := LookupByURL(ipsws, url)
						if err != nil {
							return errors.Wrap(err, "failed to get ipsw from download url")
						}

						log.WithFields(log.Fields{
							"device":  i.Identifier,
							"build":   i.BuildID,
							"version": i.Version,
							"signed":  i.Signed,
						}).Info("Getting IPSW")
						// download file
						err = api.DownloadFile(url, proxy, insecure)
						if err != nil {
							return errors.Wrap(err, "failed to download file")
						}
						// verify download
						if ok, _ := utils.Verify(i.SHA1, path.Base(i.URL)); !ok {
							return fmt.Errorf("bad download: ipsw %s sha1 hash is incorrect", path.Base(url))
						}
					} else {
						log.Warnf("ipsw already exists: %s", path.Base(url))
					}
				}
			}

		} else if len(device) > 0 || len(build) > 0 {
			if len(device) > 0 && len(build) > 0 {
				i, err := api.GetIPSW(device, build)
				if err != nil {
					return errors.Wrap(err, "failed to query ipsw.me api")
				}

				if _, err := os.Stat(path.Base(i.URL)); os.IsNotExist(err) {
					log.WithFields(log.Fields{
						"device":  i.Identifier,
						"build":   i.BuildID,
						"version": i.Version,
						"signed":  i.Signed,
					}).Info("Getting IPSW")
					err = api.DownloadFile(i.URL, proxy, insecure)
					if err != nil {
						return errors.Wrap(err, "failed to download file")
					}
					if ok, _ := utils.Verify(i.SHA1, path.Base(i.URL)); !ok {
						return fmt.Errorf("bad download: ipsw %s sha1 hash is incorrect", path.Base(i.URL))
					}
				} else {
					log.Warnf("ipsw already exists: %s", path.Base(i.URL))
				}
			}
		} else {
			log.Fatal("you must also supply a --device AND a --build")
		}
		return nil
	},
}
