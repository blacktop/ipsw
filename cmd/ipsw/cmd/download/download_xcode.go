//go:build !ios

/*
Copyright © 2025 blacktop

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
	DownloadCmd.AddCommand(xcodeCmd)
	xcodeCmd.Flags().BoolP("latest", "l", false, "Download newest XCode")
	xcodeCmd.Flags().BoolP("sim", "s", false, "Download Simulator Runtimes")

	xcodeCmd.SetHelpFunc(func(c *cobra.Command, s []string) {
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
}

// xcodeCmd represents the xcode command
var xcodeCmd = &cobra.Command{
	Use:           "xcode",
	Short:         "🚧 Download XCode 🚧",
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
		latest, _ := cmd.Flags().GetBool("latest")
		dlSim, _ := cmd.Flags().GetBool("sim")

		if dlSim {
			dvt, err := download.GetDVTDownloadableIndex()
			if err != nil {
				return err
			}

			var choices []string
			for _, dl := range dvt.Downloadables {
				choices = append(choices, dl.Name)
			}

			var choice string
			prompt := &survey.Select{
				Message:  "Select what to download:",
				Options:  choices,
				PageSize: 10,
			}
			if err := survey.AskOne(prompt, &choice); err == terminal.InterruptErr {
				log.Warn("Exiting...")
				return nil
			}

			var dl download.Downloadable
			for _, d := range dvt.Downloadables {
				if d.Name == choice {
					dl = d
				}
			}

			if dl.Source == "" {
				dl.Source = fmt.Sprintf("https://download.developer.apple.com/Developer_Tools/%s/%s.dmg", strings.ReplaceAll(dl.Name, " ", "_"), strings.ReplaceAll(dl.Name, " ", "_"))
				dl.Authentication = "virtual"
			}

			if dl.Authentication == "" {
				log.Infof("Downloading %s...", dl.Name)
				downloader := download.NewDownload(proxy, insecure, skipAll, resumeAll, restartAll, false, viper.GetBool("verbose"))
				downloader.URL = dl.Source
				downloader.DestName = path.Base(dl.Source)
				if err := downloader.Do(); err != nil {
					return err
				}
			} else {
				app := download.NewDevPortal(&download.DevConfig{
					Proxy:      proxy,
					Insecure:   insecure,
					SkipAll:    skipAll,
					ResumeAll:  resumeAll,
					RestartAll: restartAll,
					Verbose:    viper.GetBool("verbose"),
				})
				if err := app.DownloadADC(dl.Source); err != nil {
					return err
				}
			}

			install := false
			iprompt := &survey.Confirm{
				Message: "Install Simulator Runtime?",
			}
			if err := survey.AskOne(iprompt, &install); err == terminal.InterruptErr {
				log.Warn("Exiting...")
				return nil
			}

			if install {
				return utils.InstallXCodeSimRuntime(path.Base(dl.Source))
			}

			return nil
		}

		xcodes, err := download.ListXCodes()
		if err != nil {
			return err
		}

		var choice string
		if latest {
			choice = xcodes.Contents[0].Key
		} else {
			var choices []string
			for _, xcode := range xcodes.Contents {
				choices = append(choices, xcode.Key)
			}

			prompt := &survey.Select{
				Message:  "Select XCode to download:",
				Options:  choices,
				PageSize: 10,
			}
			if err := survey.AskOne(prompt, &choice); err == terminal.InterruptErr {
				log.Warn("Exiting...")
				return nil
			}
		}

		log.Infof("Downloading %s...", choice)
		sha1, err := download.QueryXcodeReleasesAPI(choice)
		if err != nil {
			return err
		}
		downloader := download.NewDownload(proxy, insecure, skipAll, resumeAll, restartAll, false, viper.GetBool("verbose"))
		downloader.URL = download.XcodeDlURL + "/" + choice
		downloader.Sha1 = sha1
		downloader.DestName = choice
		return downloader.Do()
	},
}
