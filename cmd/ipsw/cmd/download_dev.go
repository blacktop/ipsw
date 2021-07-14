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
)

func init() {
	downloadCmd.AddCommand(devCmd)

	devCmd.Flags().BoolP("sms", "", false, "Prefer SMS Two-factor authentication")
	// devCmd.Flags().BoolP("release", "", false, "Download release OSs/Apps")
	devCmd.Flags().IntP("page", "p", 20, "Page size for file lists")
}

// devCmd represents the dev command
var devCmd = &cobra.Command{
	Use:   "dev",
	Short: "Download IPSWs (and more) from https://developer.apple.com/download",
	Run: func(cmd *cobra.Command, args []string) {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		proxy, _ := cmd.Flags().GetString("proxy")
		insecure, _ := cmd.Flags().GetBool("insecure")
		skipAll, _ := cmd.Flags().GetBool("skip-all")
		removeCommas, _ := cmd.Flags().GetBool("remove-commas")

		// release, _ := cmd.Flags().GetBool("release")
		sms, _ := cmd.Flags().GetBool("sms")
		pageSize, _ := cmd.Flags().GetInt("page")

		app := download.NewDevPortal(
			proxy,
			insecure,
			skipAll,
			removeCommas,
			sms)

		// get username
		username := os.Getenv("IPSW_DEV_USERNAME")
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
		password := os.Getenv("IPSW_DEV_PASSWORD")
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

		if err := app.Login(username, password); err != nil {
			log.Fatal(err.Error())
		}

		dlType := ""
		prompt := &survey.Select{
			Message: "Choose a download type:",
			Options: []string{"beta", "release", "more"},
		}
		survey.AskOne(prompt, &dlType)

		if err := app.DownloadPrompt(dlType, pageSize); err != nil {
			log.Fatal(err.Error())
		}
	},
}
