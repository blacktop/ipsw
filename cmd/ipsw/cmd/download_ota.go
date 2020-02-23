/*
Copyright © 2020 blacktop

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
	"text/tabwriter"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/dustin/go-humanize"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	downloadCmd.AddCommand(otaDLCmd)
}

// otaDLCmd represents the ota download command
var otaDLCmd = &cobra.Command{
	Use:    "ota",
	Short:  "Download OTA betas",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		proxy, _ := cmd.Flags().GetString("proxy")
		insecure, _ := cmd.Flags().GetBool("insecure")
		// skip, _ := cmd.Flags().GetBool("yes")

		ota, err := download.NewOTA(proxy, insecure)
		if err != nil {
			return errors.Wrap(err, "failed to create itunes API")
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, '_', tabwriter.DiscardEmptyColumns)
		for _, asset := range ota.Assets {
			if len(asset.ReleaseType) == 0 {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", asset.SupportedDevices[0], asset.OSVersion, asset.Build, humanize.Bytes(uint64(asset.DownloadSize)), asset.BaseURL+asset.RelativePath)
			}
		}
		w.Flush()

		// if len(ipsws) < 1 {
		// 	log.Errorf("no ipsws found for build %s", args[0])
		// 	return nil
		// }

		// log.Debug("URLs to Download:")
		// for _, i := range ipsws {
		// 	utils.Indent(log.Debug, 2)(i.URL)
		// }

		// cont := true
		// if !skip {
		// 	cont = false
		// 	prompt := &survey.Confirm{
		// 		Message: fmt.Sprintf("You are about to download %d ipsw files. Continue?", len(ipsws)),
		// 	}
		// 	survey.AskOne(prompt, &cont)

		// }

		// if cont {
		// 	downloader := download.NewDownload(proxy, insecure)
		// 	for _, i := range ipsws {
		// 		destName := strings.Replace(path.Base(i.URL), ",", "_", -1)
		// 		if _, err := os.Stat(destName); os.IsNotExist(err) {

		// 			log.WithFields(log.Fields{
		// 				"device":  i.Device,
		// 				"build":   i.BuildID,
		// 				"version": i.Version,
		// 			}).Info("Getting IPSW")
		// 			// download file
		// 			downloader.URL = i.URL
		// 			err = downloader.Do()
		// 			if err != nil {
		// 				return errors.Wrap(err, "failed to download file")
		// 			}
		// 		} else {
		// 			log.Warnf("ipsw already exists: %s", destName)
		// 		}
		// 	}
		// }

		return nil
	},
}
