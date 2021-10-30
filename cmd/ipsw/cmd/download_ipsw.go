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

	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	downloadCmd.AddCommand(ipswCmd)
}

// ipswCmd represents the ipsw command
var ipswCmd = &cobra.Command{
	Use:   "ipsw",
	Short: "Download and parse IPSW(s) from the internets",
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		viper.BindPFlag("download.proxy", cmd.Flags().Lookup("proxy"))
		viper.BindPFlag("download.insecure", cmd.Flags().Lookup("insecure"))
		viper.BindPFlag("download.confirm", cmd.Flags().Lookup("confirm"))
		viper.BindPFlag("download.skip-all", cmd.Flags().Lookup("skip-all"))
		viper.BindPFlag("download.remove-commas", cmd.Flags().Lookup("remove-commas"))
		// settings
		proxy := viper.GetString("download.proxy")
		insecure := viper.GetBool("download.insecure")
		confirm := viper.GetBool("download.confirm")
		skipAll := viper.GetBool("download.skip-all")
		removeCommas := viper.GetBool("download.remove-commas")

		ipsws, err := filterIPSWs(cmd)
		if err != nil {
			log.Fatal(err.Error())
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
			for _, i := range ipsws {
				destName := getDestName(i.URL, removeCommas)
				if _, err := os.Stat(destName); os.IsNotExist(err) {
					log.WithFields(log.Fields{
						"device":  i.Identifier,
						"build":   i.BuildID,
						"version": i.Version,
						"signed":  i.Signed,
					}).Info("Getting IPSW")

					downloader := download.NewDownload(proxy, insecure, skipAll, Verbose)
					downloader.URL = i.URL
					downloader.Sha1 = i.SHA1
					downloader.DestName = destName

					err = downloader.Do()
					if err != nil {
						return errors.Wrap(err, "failed to download file")
					}

					// append sha1 and filename to checksums file
					f, err := os.OpenFile("checksums.txt.sha1", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
					if err != nil {
						return errors.Wrap(err, "failed to open checksums.txt.sha1")
					}
					defer f.Close()

					if _, err = f.WriteString(i.SHA1 + "  " + destName + "\n"); err != nil {
						return errors.Wrap(err, "failed to write to checksums.txt.sha1")
					}
				} else {
					log.Warnf("ipsw already exists: %s", destName)
				}
			}
		}
		return nil
	},
}
