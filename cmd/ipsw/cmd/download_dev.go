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
	"encoding/json"
	"fmt"
	"os"

	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"

	"github.com/blacktop/ipsw/internal/download"
	"github.com/spf13/cobra"
)

func init() {
	downloadCmd.AddCommand(devCmd)

	devCmd.Flags().BoolP("beta", "", false, "Download beta OSs/Apps")
}

// devCmd represents the dev command
var devCmd = &cobra.Command{
	Use:   "dev",
	Short: "Download IPSWs (and more) from https://developer.apple.com/download",
	Run: func(cmd *cobra.Command, args []string) {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		beta, _ := cmd.Flags().GetBool("beta")

		app := download.NewApp()

		username := os.Getenv("IPSW_DEV_USERNAME")
		if len(username) == 0 {
			prompt := &survey.Input{
				Message: "Please type your username",
			}
			survey.AskOne(prompt, &username)
		}

		password := os.Getenv("IPSW_DEV_PASSWORD")
		if len(password) == 0 {
			pwPrompt := &survey.Password{
				Message: "Please type your password",
			}
			survey.AskOne(pwPrompt, &password)
		}

		if err := app.Login(username, password); err != nil {
			log.Fatal(err.Error())
		}

		// if dloads, err := app.GetDownloads(); err == nil {
		// 	fmt.Println(dloads)
		// }

		ipsws, err := app.GetDevDownloads(beta)
		if err != nil {
			log.Fatal(err.Error())
		}

		dat, err := json.MarshalIndent(ipsws, "", "    ")
		if err != nil {
			log.Fatal(err.Error())
		}

		fmt.Println(string(dat))
	},
}
