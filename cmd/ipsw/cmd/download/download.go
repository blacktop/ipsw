/*
Copyright © 2018-2024 blacktop

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
package download

import (
	"fmt"
	"path"
	"strings"

	"github.com/blacktop/ipsw/internal/download"
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
	// Persistent Flags which will work for this command and all subcommands
	DownloadCmd.PersistentFlags().StringVar(&dFlg.Proxy, "proxy", "", "HTTP/HTTPS proxy")
	DownloadCmd.PersistentFlags().BoolVar(&dFlg.Insecure, "insecure", false, "do not verify ssl certs")
	DownloadCmd.PersistentFlags().BoolVarP(&dFlg.Confirm, "confirm", "y", false, "do not prompt user for confirmation")
	DownloadCmd.PersistentFlags().BoolVar(&dFlg.SkipAll, "skip-all", false, "always skip resumable IPSWs")
	DownloadCmd.PersistentFlags().BoolVar(&dFlg.ResumeAll, "resume-all", false, "always resume resumable IPSWs")
	DownloadCmd.PersistentFlags().BoolVar(&dFlg.RestartAll, "restart-all", false, "always restart resumable IPSWs")
	DownloadCmd.PersistentFlags().BoolVarP(&dFlg.RemoveCommas, "remove-commas", "_", false, "replace commas in IPSW filename with underscores")
	viper.BindPFlag("download.proxy", DownloadCmd.Flags().Lookup("proxy"))
	viper.BindPFlag("download.insecure", DownloadCmd.Flags().Lookup("insecure"))
	viper.BindPFlag("download.confirm", DownloadCmd.Flags().Lookup("confirm"))
	viper.BindPFlag("download.skip-all", DownloadCmd.Flags().Lookup("skip-all"))
	viper.BindPFlag("download.resume-all", DownloadCmd.Flags().Lookup("resume-all"))
	viper.BindPFlag("download.restart-all", DownloadCmd.Flags().Lookup("restart-all"))
	viper.BindPFlag("download.remove-commas", DownloadCmd.Flags().Lookup("remove-commas"))
	// Filters
	DownloadCmd.PersistentFlags().StringArrayVar(&dFlg.WhiteList, "white-list", []string{}, "iOS device white list")
	DownloadCmd.PersistentFlags().StringArrayVar(&dFlg.BlackList, "black-list", []string{}, "iOS device black list")
	DownloadCmd.PersistentFlags().StringVarP(&dFlg.Device, "device", "d", "", "iOS Device (i.e. iPhone11,2)")
	DownloadCmd.PersistentFlags().StringVarP(&dFlg.Model, "model", "m", "", "iOS Model (i.e. D321AP)")
	DownloadCmd.PersistentFlags().StringVarP(&dFlg.Version, "version", "v", "", "iOS Version (i.e. 12.3.1)")
	DownloadCmd.PersistentFlags().StringVarP(&dFlg.Build, "build", "b", "", "iOS BuildID (i.e. 16F203)")
	viper.BindPFlag("download.white-list", DownloadCmd.Flags().Lookup("white-list"))
	viper.BindPFlag("download.black-list", DownloadCmd.Flags().Lookup("black-list"))
	viper.BindPFlag("download.device", DownloadCmd.Flags().Lookup("device"))
	viper.BindPFlag("download.model", DownloadCmd.Flags().Lookup("model"))
	viper.BindPFlag("download.version", DownloadCmd.Flags().Lookup("version"))
	viper.BindPFlag("download.build", DownloadCmd.Flags().Lookup("build"))
}

func filterIPSWs(cmd *cobra.Command, macos bool) ([]download.IPSW, error) {

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
	if len(device) == 0 && len(version) == 0 && len(build) == 0 {
		return nil, fmt.Errorf("you must also supply a --device || --version || --build (or use --latest)")
	}
	if len(version) > 0 && len(build) > 0 {
		return nil, fmt.Errorf("you cannot supply --version AND --build (they are mutually exclusive)")
	}

	if len(version) > 0 {
		ipsws, err = download.GetAllIPSW(version)
		if err != nil {
			return nil, fmt.Errorf("failed to query ipsw.me api for ALL ipsws for version %s: %v", version, err)
		}
	} else if len(build) > 0 {
		version, err = download.GetVersion(build)
		if err != nil {
			return nil, fmt.Errorf("failed to query ipsw.me api for buildID %s => version: %v", build, err)
		}
		ipsws, err = download.GetAllIPSW(version)
		if err != nil {
			return nil, fmt.Errorf("failed to query ipsw.me api for ALL ipsws for version %s: %v", version, err)
		}
		var buildFiltered []download.IPSW
		for _, i := range ipsws {
			if strings.EqualFold(build, i.BuildID) {
				buildFiltered = append(buildFiltered, i)
			}
		}
		ipsws = buildFiltered
	} else if len(device) > 0 {
		ipsws, err = download.GetDeviceIPSWs(device)
		if err != nil {
			return nil, fmt.Errorf("failed to query ipsw.me api for device %s: %v", device, err)
		}
	}

	for _, i := range ipsws {
		if len(device) > 0 {
			if strings.EqualFold(device, i.Identifier) {
				filteredIPSWs = append(filteredIPSWs, i)
			}
		} else {
			if len(doDownload) > 0 {
				for _, doDown := range doDownload {
					if strings.HasPrefix(strings.ToLower(i.Identifier), strings.ToLower(doDown)) {
						filteredIPSWs = append(filteredIPSWs, i)
					}
				}
			} else if len(doNotDownload) > 0 {
				for _, dontDown := range doNotDownload {
					if !strings.HasPrefix(strings.ToLower(i.Identifier), strings.ToLower(dontDown)) {
						filteredIPSWs = append(filteredIPSWs, i)
					}
				}
			} else {
				filteredIPSWs = append(filteredIPSWs, i)
			}
		}
	}

	if macos {
		var furtherFilteredIPSWs []download.IPSW
		for _, i := range filteredIPSWs {
			if strings.Contains(i.Identifier, "Mac") {
				furtherFilteredIPSWs = append(furtherFilteredIPSWs, i)
			}
		}
		filteredIPSWs = furtherFilteredIPSWs
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

// DownloadCmd represents the download command
var DownloadCmd = &cobra.Command{
	Use:     "download",
	Aliases: []string{"dl"},
	Short:   "Download Apple Firmware files (and more)",
	Args:    cobra.NoArgs,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		viper.BindPFlag("color", cmd.Flags().Lookup("color"))
		viper.BindPFlag("no-color", cmd.Flags().Lookup("no-color"))
		viper.BindPFlag("verbose", cmd.Flags().Lookup("verbose"))
		viper.BindPFlag("diff-tool", cmd.Flags().Lookup("diff-tool"))
	},
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}
