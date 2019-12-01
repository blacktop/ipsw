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
)

func init() {
	downloadCmd.AddCommand(betaCmd)
}

// betaCmd represents the beta command
var betaCmd = &cobra.Command{
	Use:   "beta",
	Short: "Download beta IPSWs from the iphone wiki",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		proxy, _ := cmd.Flags().GetString("proxy")
		insecure, _ := cmd.Flags().GetBool("insecure")
		skip, _ := cmd.Flags().GetBool("yes")

		ipsws, err := api.ScrapeURLs(args[0])
		if err != nil {
			return errors.Wrap(err, "failed to query ipsw.me api")
		}

		log.Debug("URLs to Download:")
		for _, i := range ipsws {
			utils.Indent(log.Debug, 2)(i.URL)
		}

		cont := true
		if !skip {
			cont = false
			prompt := &survey.Confirm{
				Message: fmt.Sprintf("You are about to download %d ipsw files. Continue?", len(ipsws)),
			}
			survey.AskOne(prompt, &cont)

		}

		if cont {
			for _, i := range ipsws {
				destName := strings.Replace(path.Base(i.URL), ",", "_", -1)
				if _, err := os.Stat(destName); os.IsNotExist(err) {

					log.WithFields(log.Fields{
						"device":  i.Device,
						"build":   i.BuildID,
						"version": i.Version,
					}).Info("Getting IPSW")
					// download file
					err = api.NewDownload(i.URL, "", proxy, insecure).Do()
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
