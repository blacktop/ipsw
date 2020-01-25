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
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	downloadCmd.AddCommand(latestCmd)

	// latestCmd.Flags().BoolP("yes", "y", false, "do not prompt user")
}

// latestCmd represents the latest command
var latestCmd = &cobra.Command{
	Use:   "latest",
	Short: "Download latest release version",
	RunE: func(cmd *cobra.Command, args []string) error {
		var err error
		var builds []download.Build
		var filteredBuilds []download.Build

		proxy, _ := cmd.Flags().GetString("proxy")
		insecure, _ := cmd.Flags().GetBool("insecure")
		skip, _ := cmd.Flags().GetBool("yes")

		// filters
		//version, _ := cmd.Flags().GetString("version")
		device, _ := cmd.Flags().GetString("device")
		doDownload, _ := cmd.Flags().GetStringArray("white-list")
		doNotDownload, _ := cmd.Flags().GetStringArray("black-list")
		//build, _ := cmd.Flags().GetString("build")

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		itunes, err := download.NewiTunesVersionMaster()
		if err != nil {
			return errors.Wrap(err, "failed to create itunes API")
		}

		builds, err = itunes.GetLatestBuilds(device)
		if err != nil {
			return errors.Wrap(err, "failed to get the latest builds")
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

		log.Debug("URLs to Download:")
		for _, b := range filteredBuilds {
			utils.Indent(log.Debug, 1)(b.FirmwareURL)
		}

		cont := true
		if !skip {
			cont = false
			prompt := &survey.Confirm{
				Message: fmt.Sprintf("You are about to download %d ipsw files. Continue?", len(filteredBuilds)),
			}
			survey.AskOne(prompt, &cont)
		}

		if cont {
			downloader := download.NewDownload(proxy, insecure)
			for _, build := range filteredBuilds {
				destName := strings.Replace(path.Base(build.FirmwareURL), ",", "_", -1)
				if _, err := os.Stat(destName); os.IsNotExist(err) {
					log.WithFields(log.Fields{
						"device":  build.Identifier,
						"build":   build.BuildVersion,
						"version": build.ProductVersion,
					}).Info("Getting IPSW")
					// download file
					downloader.URL = build.FirmwareURL
					downloader.Sha1 = build.FirmwareSHA1
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
					if _, err = f.WriteString(build.FirmwareSHA1 + "  " + destName + "\n"); err != nil {
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
