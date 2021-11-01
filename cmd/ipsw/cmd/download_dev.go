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
	"os"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/apex/log"

	"github.com/blacktop/ipsw/internal/download"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	downloadCmd.AddCommand(devCmd)

	devCmd.Flags().StringArray("watch", []string{viper.GetString("IPSW_DEV_PORTAL_WATCH_LIST")}, "dev portal type to watch")
	viper.BindPFlag("download.dev.watch", devCmd.Flags().Lookup("watch"))
	devCmd.Flags().Bool("release", false, "Download 'Release' OSs/Apps")
	viper.BindPFlag("download.dev.release", devCmd.Flags().Lookup("release"))
	devCmd.Flags().Bool("beta", false, "Download 'Beta' OSs/Apps")
	viper.BindPFlag("download.dev.beta", devCmd.Flags().Lookup("beta"))
	devCmd.Flags().Bool("more", false, "Download 'More' OSs/Apps")
	viper.BindPFlag("download.dev.more", devCmd.Flags().Lookup("more"))

	devCmd.Flags().IntP("page", "p", 20, "Page size for file lists")
	viper.BindPFlag("download.dev.page", devCmd.Flags().Lookup("page"))
	devCmd.Flags().Bool("sms", false, "Prefer SMS Two-factor authentication")
	viper.BindPFlag("download.dev.sms", devCmd.Flags().Lookup("sms"))
}

// devCmd represents the dev command
var devCmd = &cobra.Command{
	Use:   "dev",
	Short: "Download IPSWs (and more) from https://developer.apple.com/download",
	Run: func(cmd *cobra.Command, args []string) {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		viper.BindPFlag("download.proxy", cmd.Flags().Lookup("proxy"))
		viper.BindPFlag("download.insecure", cmd.Flags().Lookup("insecure"))
		// viper.BindPFlag("download.confirm", cmd.Flags().Lookup("confirm"))
		viper.BindPFlag("download.skip-all", cmd.Flags().Lookup("skip-all"))
		viper.BindPFlag("download.resume-all", cmd.Flags().Lookup("resume-all"))
		viper.BindPFlag("download.restart-all", cmd.Flags().Lookup("restart-all"))
		viper.BindPFlag("download.remove-commas", cmd.Flags().Lookup("remove-commas"))

		// settings
		proxy := viper.GetString("download.proxy")
		insecure := viper.GetBool("download.insecure")
		// confirm := viper.GetBool("download.confirm")
		skipAll := viper.GetBool("download.skip-all")
		resumeAll := viper.GetBool("download.resume-all")
		restartAll := viper.GetBool("download.restart-all")
		removeCommas := viper.GetBool("download.remove-commas")

		release := viper.GetBool("download.dev.release")
		beta := viper.GetBool("download.dev.beta")
		more := viper.GetBool("download.dev.more")
		watchList := viper.GetStringSlice("download.dev.watchList")
		pageSize := viper.GetInt("download.dev.pageSize")

		sms, _ := cmd.Flags().GetBool("sms")

		app := download.NewDevPortal(&download.DevConfig{
			Proxy:        proxy,
			Insecure:     insecure,
			SkipAll:      skipAll,
			ResumeAll:    resumeAll,
			RestartAll:   restartAll,
			RemoveCommas: removeCommas,
			PreferSMS:    sms,
			PageSize:     pageSize,
			Beta:         beta,
			WatchList:    watchList,
		})

		username := viper.GetString("download.dev.username")
		password := viper.GetString("download.dev.password")

		if len(viper.GetString("session_id")) == 0 {
			// get username
			if len(username) == 0 {
				prompt := &survey.Input{
					Message: "Please type your username:",
				}
				if err := survey.AskOne(prompt, &username); err != nil {
					if err == terminal.InterruptErr {
						log.Warn("Exiting...")
						os.Exit(0)
					}
					log.Fatal(err.Error())
				}
			}
			// get password
			if len(password) == 0 {
				prompt := &survey.Password{
					Message: "Please type your password:",
				}
				if err := survey.AskOne(prompt, &password); err != nil {
					if err == terminal.InterruptErr {
						log.Warn("Exiting...")
						os.Exit(0)
					}
					log.Fatal(err.Error())
				}
			}
		}

		if err := app.Login(username, password); err != nil {
			log.Fatal(err.Error())
		}

		if len(watchList) > 0 {
			if err := app.Watch(); err != nil {
				log.Fatal(err.Error())
			}
		}

		dlType := ""
		if release {
			dlType = "release"
		} else if beta {
			dlType = "beta"
		} else if more {
			dlType = "more"
		} else {

			prompt := &survey.Select{
				Message: "Choose a download type:",
				Options: []string{"beta", "release", "more"},
			}
			if err := survey.AskOne(prompt, &dlType); err != nil {
				if err == terminal.InterruptErr {
					log.Warn("Exiting...")
					os.Exit(0)
				}
				log.Fatal(err.Error())
			}

		}

		if err := app.DownloadPrompt(dlType); err != nil {
			log.Fatal(err.Error())
		}
	},
}
