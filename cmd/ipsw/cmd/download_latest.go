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
	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/api"
	"github.com/blacktop/ipsw/utils"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"os"
	"path"
)

func init() {
	downloadCmd.AddCommand(latestCmd)

	latestCmd.Flags().BoolP("yes", "y", false, "do not prompt user")
}

// latestCmd represents the latest command
var latestCmd = &cobra.Command{
	Use:   "latest",
	Short: "Download latest release version",
	RunE: func(cmd *cobra.Command, args []string) error {
		var err error
		var builds []api.Build

		proxy, _ := cmd.Flags().GetString("proxy")
		insecure, _ := cmd.Flags().GetBool("insecure")
		skip, _ := cmd.Flags().GetBool("yes")

		// filters
		//version, _ := cmd.Flags().GetString("version")
		//device, _ := cmd.Flags().GetString("device")
		//build, _ := cmd.Flags().GetString("build")

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		itunes, err := api.NewiTunesVersionMaster()
		if err != nil {
			return errors.Wrap(err, "failed to create itunes API")
		}

		builds, err = itunes.GetLatestBuilds()
		if err != nil {
			return errors.Wrap(err, "failed to get the latest builds")
		}

		log.Debug("URLS TO DOWNLOAD:")
		for _, b := range builds {
			utils.Indent(log.Debug)(b.FirmwareURL)
		}

		cont := true
		if !skip {
			cont = false
			prompt := &survey.Confirm{
				Message: fmt.Sprintf("You are about to download %d ipsw files. Continue?", len(builds)),
			}
			survey.AskOne(prompt, &cont)
		}

		if cont {
			for _, build := range builds {
				if _, err := os.Stat(path.Base(build.FirmwareURL)); os.IsNotExist(err) {
					log.WithFields(log.Fields{
						"device":  build.Identifier,
						"build":   build.BuildVersion,
						"version": build.ProductVersion,
					}).Info("Getting IPSW")
					// download file
					err = api.DownloadFile(build.FirmwareURL, proxy, insecure)
					if err != nil {
						return errors.Wrap(err, "failed to download file")
					}
					// verify download
					if ok, _ := utils.Verify(build.FirmwareSHA1, path.Base(build.FirmwareURL)); !ok {
						return fmt.Errorf("bad download: ipsw %s sha1 hash is incorrect", path.Base(build.FirmwareURL))
					}
				} else {
					log.Warnf("ipsw already exists: %s", path.Base(build.FirmwareURL))
				}
			}
		}

		return nil
	},
}
