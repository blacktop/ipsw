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
	"path"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(downloadCmd)
	// Persistent Flags which will work for this command and all subcommands
	downloadCmd.PersistentFlags().String("proxy", viper.GetString("download.proxy"), "HTTP/HTTPS proxy")
	downloadCmd.PersistentFlags().Bool("insecure", viper.GetBool("download.insecure"), "do not verify ssl certs")
	// Filters
	downloadCmd.PersistentFlags().StringArray("white-list", viper.GetStringSlice("download.white-list"), "iOS device white list")
	downloadCmd.PersistentFlags().StringArray("black-list", viper.GetStringSlice("download.black-list"), "iOS device black list")
	downloadCmd.PersistentFlags().BoolP("confirm", "y", viper.GetBool("download.confirm"), "do not prompt user for confirmation")
	downloadCmd.PersistentFlags().BoolP("skip-all", "s", viper.GetBool("download.skip-all"), "always skip resumable IPSWs")
	downloadCmd.PersistentFlags().BoolP("remove-commas", "_", viper.GetBool("download.remove-commas"), "replace commas in IPSW filename with underscores")
	downloadCmd.PersistentFlags().StringP("device", "d", viper.GetString("download.device"), "iOS Device (i.e. iPhone11,2)")
	downloadCmd.PersistentFlags().StringP("model", "m", viper.GetString("download.model"), "iOS Model (i.e. D321AP)")
	downloadCmd.PersistentFlags().StringP("version", "v", viper.GetString("download.version"), "iOS Version (i.e. 12.3.1)")
	viper.BindPFlag("download.version", downloadCmd.Flags().Lookup("version"))
	downloadCmd.PersistentFlags().StringP("build", "b", viper.GetString("download.build"), "iOS BuildID (i.e. 16F203)")
}

func filterIPSWs(cmd *cobra.Command) ([]download.IPSW, error) {

	var err error
	var ipsws []download.IPSW
	var filteredIPSWs []download.IPSW

	// filters
	device, _ := cmd.Flags().GetString("device")
	// model, _ := cmd.Flags().GetString("model")
	version, _ := cmd.Flags().GetString("version")
	build, _ := cmd.Flags().GetString("build")
	doDownload, _ := cmd.Flags().GetStringArray("white-list")
	doNotDownload, _ := cmd.Flags().GetStringArray("black-list")

	if len(version) > 0 && len(build) > 0 {
		log.Fatal("you cannot supply a --version AND a --build (they are mutually exclusive)")
	}

	if len(version) > 0 {
		ipsws, err = download.GetAllIPSW(version)
		if err != nil {
			return nil, errors.Wrap(err, "failed to query ipsw.me api")
		}
	} else if len(build) > 0 {
		version, err = download.GetVersion(build)
		if err != nil {
			return nil, errors.Wrap(err, "failed to query ipsw.me api")
		}
		ipsws, err = download.GetAllIPSW(version)
		if err != nil {
			return nil, errors.Wrap(err, "failed to query ipsw.me api")
		}
	} else {
		return nil, fmt.Errorf("you must also supply a --version OR a --build (or use download latest)")
	}

	for _, i := range ipsws {
		if len(device) > 0 {
			if strings.EqualFold(device, i.Identifier) {
				filteredIPSWs = append(filteredIPSWs, i)
			}
		} else {
			if len(doDownload) > 0 {
				if utils.StrSliceContains(doDownload, i.Identifier) {
					filteredIPSWs = append(filteredIPSWs, i)
				}
			} else if len(doNotDownload) > 0 {
				if !utils.StrSliceContains(doNotDownload, i.Identifier) {
					filteredIPSWs = append(filteredIPSWs, i)
				}
			} else {
				filteredIPSWs = append(filteredIPSWs, i)
			}
		}
	}

	unique := make(map[string]bool, len(filteredIPSWs))
	uniqueIPSWs := make([]download.IPSW, len(unique))
	for _, i := range filteredIPSWs {
		if len(i.URL) != 0 {
			if !unique[i.URL] {
				uniqueIPSWs = append(uniqueIPSWs, i)
				unique[i.URL] = true
			}
		}
	}

	if len(uniqueIPSWs) == 0 {
		return nil, fmt.Errorf("filter flags matched 0 IPSWs")
	}

	return uniqueIPSWs, nil
}

func getDestName(url string, removeCommas bool) string {
	if removeCommas {
		return strings.Replace(path.Base(url), ",", "_", -1)
	}
	return path.Base(url)
}

// downloadCmd represents the download command
var downloadCmd = &cobra.Command{
	Use:   "download",
	Short: "Download Apple Firmware files (and more)",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}
