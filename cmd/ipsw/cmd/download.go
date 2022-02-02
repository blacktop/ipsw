/*
Copyright © 2018-2022 blacktop

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

	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type downloadFlags struct {
	Proxy        string
	Insecure     bool
	Confirm      bool
	SkipAll      bool
	ResumeAll    bool
	RestartAll   bool
	RemoveCommas bool

	WhiteList []string
	BlackList []string
	Device    string
	Model     string
	Version   string
	Build     string
}

var dFlg downloadFlags

func init() {
	rootCmd.AddCommand(downloadCmd)
	// Persistent Flags which will work for this command and all subcommands
	downloadCmd.PersistentFlags().StringVar(&dFlg.Proxy, "proxy", "", "HTTP/HTTPS proxy")
	downloadCmd.PersistentFlags().BoolVar(&dFlg.Insecure, "insecure", false, "do not verify ssl certs")
	downloadCmd.PersistentFlags().BoolVarP(&dFlg.Confirm, "confirm", "y", false, "do not prompt user for confirmation")
	downloadCmd.PersistentFlags().BoolVar(&dFlg.SkipAll, "skip-all", false, "always skip resumable IPSWs")
	downloadCmd.PersistentFlags().BoolVar(&dFlg.ResumeAll, "resume-all", false, "always resume resumable IPSWs")
	downloadCmd.PersistentFlags().BoolVar(&dFlg.RestartAll, "restart-all", false, "always restart resumable IPSWs")
	downloadCmd.PersistentFlags().BoolVarP(&dFlg.RemoveCommas, "remove-commas", "_", false, "replace commas in IPSW filename with underscores")
	viper.BindPFlag("download.proxy", downloadCmd.Flags().Lookup("proxy"))
	viper.BindPFlag("download.insecure", downloadCmd.Flags().Lookup("insecure"))
	viper.BindPFlag("download.confirm", downloadCmd.Flags().Lookup("confirm"))
	viper.BindPFlag("download.skip-all", downloadCmd.Flags().Lookup("skip-all"))
	viper.BindPFlag("download.resume-all", downloadCmd.Flags().Lookup("resume-all"))
	viper.BindPFlag("download.restart-all", downloadCmd.Flags().Lookup("restart-all"))
	viper.BindPFlag("download.remove-commas", downloadCmd.Flags().Lookup("remove-commas"))
	// Filters
	downloadCmd.PersistentFlags().StringArrayVar(&dFlg.WhiteList, "white-list", []string{}, "iOS device white list")
	downloadCmd.PersistentFlags().StringArrayVar(&dFlg.BlackList, "black-list", []string{}, "iOS device black list")
	downloadCmd.PersistentFlags().StringVarP(&dFlg.Device, "device", "d", "", "iOS Device (i.e. iPhone11,2)")
	downloadCmd.PersistentFlags().StringVarP(&dFlg.Model, "model", "m", "", "iOS Model (i.e. D321AP)")
	downloadCmd.PersistentFlags().StringVarP(&dFlg.Version, "version", "v", "", "iOS Version (i.e. 12.3.1)")
	downloadCmd.PersistentFlags().StringVarP(&dFlg.Build, "build", "b", "", "iOS BuildID (i.e. 16F203)")
	viper.BindPFlag("download.white-list", downloadCmd.Flags().Lookup("white-list"))
	viper.BindPFlag("download.black-list", downloadCmd.Flags().Lookup("black-list"))
	viper.BindPFlag("download.device", downloadCmd.Flags().Lookup("device"))
	viper.BindPFlag("download.model", downloadCmd.Flags().Lookup("model"))
	viper.BindPFlag("download.version", downloadCmd.Flags().Lookup("version"))
	viper.BindPFlag("download.build", downloadCmd.Flags().Lookup("build"))
}

func filterIPSWs(cmd *cobra.Command) ([]download.IPSW, error) {

	var err error
	var ipsws []download.IPSW
	var filteredIPSWs []download.IPSW

	viper.BindPFlag("download.white-list", cmd.Flags().Lookup("white-list"))
	viper.BindPFlag("download.black-list", cmd.Flags().Lookup("black-list"))
	viper.BindPFlag("download.confirm", cmd.Flags().Lookup("confirm"))
	viper.BindPFlag("download.skip-all", cmd.Flags().Lookup("skip-all"))
	viper.BindPFlag("download.resume-all", cmd.Flags().Lookup("resume-all"))
	viper.BindPFlag("download.restart-all", cmd.Flags().Lookup("restart-all"))
	viper.BindPFlag("download.remove-commas", cmd.Flags().Lookup("remove-commas"))
	viper.BindPFlag("download.device", cmd.Flags().Lookup("device"))
	viper.BindPFlag("download.model", cmd.Flags().Lookup("model"))
	viper.BindPFlag("download.version", cmd.Flags().Lookup("version"))
	viper.BindPFlag("download.build", cmd.Flags().Lookup("build"))

	// filters
	device := viper.GetString("download.device")
	// model := viper.GetString("download.model")
	version := viper.GetString("download.version")
	build := viper.GetString("download.build")
	doDownload := viper.GetStringSlice("download.white-list")
	doNotDownload := viper.GetStringSlice("download.black-list")

	// verify args
	if len(version) == 0 && len(build) == 0 {
		return nil, fmt.Errorf("you must also supply a --version OR a --build (or use --latest)")
	}
	if len(version) > 0 && len(build) > 0 {
		return nil, fmt.Errorf("you cannot supply a --version AND a --build (they are mutually exclusive)")
	}

	if len(version) > 0 {
		ipsws, err = download.GetAllIPSW(version)
		if err != nil {
			return nil, fmt.Errorf("failed to query ipsw.me api for ALL ipsws: %v", err)
		}
	} else { // using build
		version, err = download.GetVersion(build)
		if err != nil {
			return nil, fmt.Errorf("failed to query ipsw.me api for buildID => version: %v", err)
		}
		ipsws, err = download.GetAllIPSW(version)
		if err != nil {
			return nil, fmt.Errorf("failed to query ipsw.me api for ALL ipsws: %v", err)
		}
	}

	for _, i := range ipsws {
		if len(device) > 0 {
			if strings.EqualFold(device, i.Identifier) {
				filteredIPSWs = append(filteredIPSWs, i)
			}
		} else {
			if len(doDownload) > 0 {
				if utils.StrSliceHas(doDownload, i.Identifier) {
					filteredIPSWs = append(filteredIPSWs, i)
				}
			} else if len(doNotDownload) > 0 {
				if !utils.StrSliceHas(doNotDownload, i.Identifier) {
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
