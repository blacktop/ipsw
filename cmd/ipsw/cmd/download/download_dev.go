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
package download

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/apex/log"

	"github.com/blacktop/ipsw/internal/download"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DownloadCmd.AddCommand(devCmd)

	devCmd.Flags().StringArray("watch", []string{}, "dev portal type to watch")
	devCmd.Flags().Bool("more", false, "Download 'More' OSs/Apps")
	devCmd.Flags().IntP("page", "p", 20, "Page size for file lists")
	devCmd.Flags().Bool("sms", false, "Prefer SMS Two-factor authentication")
	devCmd.Flags().Bool("json", false, "Output downloadable items as JSON")
	devCmd.Flags().Bool("pretty", false, "Pretty print JSON")
	devCmd.Flags().StringP("output", "o", "", "Folder to download files to")
	viper.BindPFlag("download.dev.watch", devCmd.Flags().Lookup("watch"))
	viper.BindPFlag("download.dev.more", devCmd.Flags().Lookup("more"))
	viper.BindPFlag("download.dev.page", devCmd.Flags().Lookup("page"))
	viper.BindPFlag("download.dev.sms", devCmd.Flags().Lookup("sms"))
	viper.BindPFlag("download.dev.json", devCmd.Flags().Lookup("json"))
	viper.BindPFlag("download.dev.pretty", devCmd.Flags().Lookup("pretty"))
	viper.BindPFlag("download.dev.output", devCmd.Flags().Lookup("output"))
}

// devCmd represents the dev command
var devCmd = &cobra.Command{
	Use:           "dev",
	Short:         "Download IPSWs (and more) from https://developer.apple.com/download",
	SilenceUsage:  false,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		viper.BindPFlag("download.proxy", cmd.Flags().Lookup("proxy"))
		viper.BindPFlag("download.insecure", cmd.Flags().Lookup("insecure"))
		viper.BindPFlag("download.confirm", cmd.Flags().Lookup("confirm"))
		viper.BindPFlag("download.skip-all", cmd.Flags().Lookup("skip-all"))
		viper.BindPFlag("download.resume-all", cmd.Flags().Lookup("resume-all"))
		viper.BindPFlag("download.restart-all", cmd.Flags().Lookup("restart-all"))
		viper.BindPFlag("download.remove-commas", cmd.Flags().Lookup("remove-commas"))
		viper.BindPFlag("download.white-list", cmd.Flags().Lookup("white-list"))
		viper.BindPFlag("download.black-list", cmd.Flags().Lookup("black-list"))
		viper.BindPFlag("download.device", cmd.Flags().Lookup("device"))
		viper.BindPFlag("download.model", cmd.Flags().Lookup("model"))
		viper.BindPFlag("download.version", cmd.Flags().Lookup("version"))
		viper.BindPFlag("download.build", cmd.Flags().Lookup("build"))

		// settings
		proxy := viper.GetString("download.proxy")
		insecure := viper.GetBool("download.insecure")
		// confirm := viper.GetBool("download.confirm")
		skipAll := viper.GetBool("download.skip-all")
		resumeAll := viper.GetBool("download.resume-all")
		restartAll := viper.GetBool("download.restart-all")
		removeCommas := viper.GetBool("download.remove-commas")
		// flags
		watchList := viper.GetStringSlice("download.dev.watch")
		more := viper.GetBool("download.dev.more")
		pageSize := viper.GetInt("download.dev.page")
		sms := viper.GetBool("download.dev.sms")
		asJSON := viper.GetBool("download.dev.json")
		prettyJSON := viper.GetBool("download.dev.pretty")
		output := viper.GetString("download.dev.output")

		app := download.NewDevPortal(&download.DevConfig{
			Proxy:        proxy,
			Insecure:     insecure,
			SkipAll:      skipAll,
			ResumeAll:    resumeAll,
			RestartAll:   restartAll,
			RemoveCommas: removeCommas,
			PreferSMS:    sms,
			PageSize:     pageSize,
			WatchList:    watchList,
			Verbose:      viper.GetBool("verbose"),
		})

		username := viper.GetString("download.dev.username")
		password := viper.GetString("download.dev.password")

		if len(viper.GetString("download.dev.session_id")) == 0 {
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
					return err
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
					return err
				}
			}
		}

		if err := app.Login(username, password); err != nil {
			return err
		}

		if len(watchList) > 0 {
			if err := app.Watch(); err != nil {
				return err
			}
		}

		dlType := ""
		if more {
			dlType = "more"
		} else {
			prompt := &survey.Select{
				Message: "Choose a download type:",
				Options: []string{"OSes (iOS, macOS, tvOS...)", "More (XCode, KDKs...)"},
			}
			if err := survey.AskOne(prompt, &dlType); err != nil {
				if err == terminal.InterruptErr {
					log.Warn("Exiting...")
					os.Exit(0)
				}
				return err
			}
			if strings.Contains(dlType, "More") {
				dlType = "more"
			}
		}

		if asJSON {
			if dat, err := app.GetDownloadsAsJSON(dlType, prettyJSON); err != nil {
				return err
			} else {
				if len(output) > 0 {
					fpath := filepath.Join(output, fmt.Sprintf("dev_portal_%s.json", dlType))
					log.Infof("Creating %s", fpath)
					if err := os.WriteFile(fpath, dat, 0660); err != nil {
						return err
					}
				} else {
					fmt.Println(string(dat))
				}
			}
		} else {
			if err := app.DownloadPrompt(dlType); err != nil {
				return err
			}
		}
		return nil
	},
}
