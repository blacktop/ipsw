/*
Copyright © 2024 blacktop

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
	"os"
	"path"
	"path/filepath"
	"sort"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DownloadCmd.AddCommand(downloadKdkCmd)
	downloadKdkCmd.Flags().Bool("host", false, "Download KDK for current host OS")
	downloadKdkCmd.Flags().StringP("build", "b", "", "Download KDK for build")
	downloadKdkCmd.Flags().BoolP("latest", "l", false, "Download latest KDK")
	downloadKdkCmd.Flags().BoolP("all", "a", false, "Download all KDKs")
	downloadKdkCmd.Flags().BoolP("install", "i", false, "Install KDK after download")
	downloadKdkCmd.Flags().StringP("output", "o", "", "Folder to download files to")
	downloadKdkCmd.MarkFlagDirname("output")
	downloadKdkCmd.MarkFlagsMutuallyExclusive("host", "build", "latest", "all")
	downloadKdkCmd.SetHelpFunc(func(c *cobra.Command, s []string) {
		DownloadCmd.PersistentFlags().MarkHidden("white-list")
		DownloadCmd.PersistentFlags().MarkHidden("black-list")
		DownloadCmd.PersistentFlags().MarkHidden("device")
		DownloadCmd.PersistentFlags().MarkHidden("model")
		DownloadCmd.PersistentFlags().MarkHidden("version")
		DownloadCmd.PersistentFlags().MarkHidden("build")
		DownloadCmd.PersistentFlags().MarkHidden("confirm")
		DownloadCmd.PersistentFlags().MarkHidden("remove-commas")
		c.Parent().HelpFunc()(c, s)
	})
	viper.BindPFlag("download.kdk.host", downloadKdkCmd.Flags().Lookup("host"))
	viper.BindPFlag("download.kdk.build", downloadKdkCmd.Flags().Lookup("build"))
	viper.BindPFlag("download.kdk.latest", downloadKdkCmd.Flags().Lookup("latest"))
	viper.BindPFlag("download.kdk.all", downloadKdkCmd.Flags().Lookup("all"))
	viper.BindPFlag("download.kdk.install", downloadKdkCmd.Flags().Lookup("install"))
	viper.BindPFlag("download.kdk.output", downloadKdkCmd.Flags().Lookup("output"))
}

// downloadKdkCmd represents the kdk command
var downloadKdkCmd = &cobra.Command{
	Use:           "kdk",
	Short:         "Download KDKs",
	SilenceUsage:  true,
	SilenceErrors: true,
	Hidden:        true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		viper.BindPFlag("download.proxy", cmd.Flags().Lookup("proxy"))
		viper.BindPFlag("download.insecure", cmd.Flags().Lookup("insecure"))
		viper.BindPFlag("download.skip-all", cmd.Flags().Lookup("skip-all"))
		viper.BindPFlag("download.resume-all", cmd.Flags().Lookup("resume-all"))
		viper.BindPFlag("download.restart-all", cmd.Flags().Lookup("restart-all"))

		// settings
		proxy := viper.GetString("download.proxy")
		insecure := viper.GetBool("download.insecure")
		skipAll := viper.GetBool("download.skip-all")
		resumeAll := viper.GetBool("download.resume-all")
		restartAll := viper.GetBool("download.restart-all")
		// flags
		forHost := viper.GetBool("download.kdk.host")
		forBuild := viper.GetString("download.kdk.build")
		latest := viper.GetBool("download.kdk.latest")
		all := viper.GetBool("download.kdk.all")
		install := viper.GetBool("download.kdk.install")
		output := viper.GetString("download.kdk.output")

		kdks, err := download.ListKDKs()
		if err != nil {
			return err
		}

		var dlKDKs []download.KDK

		if forHost {
			binfo, err := utils.GetBuildInfo()
			if err != nil {
				return fmt.Errorf("failed to get build info: %v", err)
			}
			found := false
			for _, kdk := range kdks {
				if kdk.Version == binfo.ProductVersion && kdk.Build == binfo.BuildVersion {
					dlKDKs = append(dlKDKs, kdk)
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("failed to find KDK for %s (%s)", binfo.ProductVersion, binfo.BuildVersion)
			}
		} else if len(forBuild) > 0 {
			found := false
			for _, kdk := range kdks {
				if kdk.Build == forBuild {
					dlKDKs = append(dlKDKs, kdk)
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("failed to find KDK for '%s'", forBuild)
			}
		} else if latest {
			// sort by seen date
			sort.Sort(kdks)
			dlKDKs = append(dlKDKs, kdks[0])
		} else if all {
			dlKDKs = append(dlKDKs, kdks...)
		} else {
			var choices []string
			for _, kdk := range kdks {
				choices = append(choices, kdk.Name)
			}

			var choice string
			prompt := &survey.Select{
				Message:  "Select KDK to download:",
				Options:  choices,
				PageSize: 10,
			}
			if err := survey.AskOne(prompt, &choice); err == terminal.InterruptErr {
				log.Warn("Exiting...")
				return nil
			}

			for _, kdk := range kdks {
				if kdk.Name == choice {
					dlKDKs = append(dlKDKs, kdk)
					break
				}
			}
		}

		if len(dlKDKs) > 1 && install {
			log.Warn("Installing multiple KDKs")
		}

		for _, kdk := range dlKDKs {
			destName := path.Base(kdk.URL)
			if len(output) > 0 {
				destName = filepath.Join(filepath.Clean(output), path.Base(kdk.URL))
			}
			if err := os.MkdirAll(filepath.Dir(destName), 0755); err != nil {
				return fmt.Errorf("failed to create directory: %v", err)
			}

			if _, err := os.Stat(destName); os.IsNotExist(err) {
				log.Infof("Downloading to %s...", destName)
				downloader := download.NewDownload(proxy, insecure, skipAll, resumeAll, restartAll, false, viper.GetBool("verbose"))
				downloader.URL = kdk.URL
				downloader.DestName = destName
				if err := downloader.Do(); err != nil {
					return err
				}
			} else {
				log.Warnf("File already exists: %s", destName)
			}

			if install {
				log.Infof("Installing %s...", destName)
				if err := utils.InstallKDK(destName); err != nil {
					return err
				}
			}
		}

		return nil
	},
}
