//go:build !ios

/*
Copyright © 2026 blacktop

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
	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DownloadCmd.AddCommand(downloadXcodeCmd)
	// Download behavior flags
	downloadXcodeCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	downloadXcodeCmd.Flags().Bool("insecure", false, "do not verify ssl certs")
	downloadXcodeCmd.Flags().Bool("skip-all", false, "continue past files locked by another download process")
	downloadXcodeCmd.Flags().Bool("ignore-sha1", false, "skip SHA-1 verification")
	downloadXcodeCmd.Flags().Bool("restart-all", false, "always restart resumable IPSWs")
	// Command-specific flags
	downloadXcodeCmd.Flags().BoolP("latest", "l", false, "Download newest Xcode")
	downloadXcodeCmd.Flags().BoolP("sim", "s", false, "Download Simulator Runtimes")
	downloadXcodeCmd.Flags().StringP("runtime", "r", "", "Name of simulator runtime to download")
	// Bind persistent flags
	viper.BindPFlag("download.xcode.proxy", downloadXcodeCmd.Flags().Lookup("proxy"))
	viper.BindPFlag("download.xcode.insecure", downloadXcodeCmd.Flags().Lookup("insecure"))
	viper.BindPFlag("download.xcode.skip-all", downloadXcodeCmd.Flags().Lookup("skip-all"))
	viper.BindPFlag("download.xcode.ignore-sha1", downloadXcodeCmd.Flags().Lookup("ignore-sha1"))
	viper.BindPFlag("download.xcode.restart-all", downloadXcodeCmd.Flags().Lookup("restart-all"))
	// Bind command-specific flags
	viper.BindPFlag("download.xcode.latest", downloadXcodeCmd.Flags().Lookup("latest"))
	viper.BindPFlag("download.xcode.sim", downloadXcodeCmd.Flags().Lookup("sim"))
	viper.BindPFlag("download.xcode.runtime", downloadXcodeCmd.Flags().Lookup("runtime"))
}

// downloadXcodeCmd represents the xcode command
var downloadXcodeCmd = &cobra.Command{
	Use:   "xcode",
	Short: "🚧 Download Xcode 🚧",
	Example: heredoc.Doc(`
		# Download latest Xcode
		❯ ipsw download xcode --latest

		# Download Xcode interactively
		❯ ipsw download xcode

		# Download simulator runtimes
		❯ ipsw download xcode --sim

		# Download specific simulator runtime
		❯ ipsw download xcode --sim --runtime "iOS 17.0"
	`),
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		// settings
		proxy := viper.GetString("download.xcode.proxy")
		insecure := viper.GetBool("download.xcode.insecure")
		skipAll := viper.GetBool("download.xcode.skip-all")
		ignoreSha1 := viper.GetBool("download.xcode.ignore-sha1")
		restartAll := viper.GetBool("download.xcode.restart-all")
		// flags
		latest := viper.GetBool("download.xcode.latest")
		dlSim := viper.GetBool("download.xcode.sim")
		runtime := viper.GetString("download.xcode.runtime")

		if dlSim {
			dvt, err := download.GetDVTDownloadableIndex()
			if err != nil {
				return err
			}

			var choices []string
			for _, dl := range dvt.Downloadables {
				choices = append(choices, dl.Name)
			}

			var dl download.Downloadable
			if runtime != "" {
				for _, d := range dvt.Downloadables {
					if d.Name == runtime {
						dl = d
						break
					}
				}
			} else {
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

				for _, d := range dvt.Downloadables {
					if d.Name == choice {
						dl = d
					}
				}
			}
			if dl.Source == "" {
				dl.Source = fmt.Sprintf("https://download.developer.apple.com/Developer_Tools/%s/%s.dmg", strings.ReplaceAll(dl.Name, " ", "_"), strings.ReplaceAll(dl.Name, " ", "_"))
				dl.Authentication = "virtual"
			}
			destName := path.Base(dl.Source)

			var status download.Status
			if dl.Authentication == "" {
				log.Infof("Downloading %s...", dl.Name)
				downloader := download.NewDownloadWithProfile(
					download.AppleCDNProfile, proxy, insecure, skipAll, restartAll, ignoreSha1)
				defer downloader.Close()
				downloader.URL = dl.Source
				downloader.DestName = destName
				if status, err = downloader.DoContext(cmd.Context()); err != nil {
					return err
				}
			} else {
				app := download.NewDevPortal(&download.DevConfig{
					Context:    cmd.Context(),
					Proxy:      proxy,
					Insecure:   insecure,
					SkipAll:    skipAll,
					RestartAll: restartAll,
				})
				defer app.Close()
				if status, err = app.DownloadADC(dl.Source); err != nil {
					return err
				}
			}
			if status != download.Downloaded {
				log.Warnf("Skipping installation while %s is being downloaded by another process", destName)
				return nil
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
				return utils.InstallXCodeSimRuntime(destName)
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
				Message:  "Select Xcode to download:",
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
		downloader := download.NewDownloadWithProfile(
			download.AppleCDNProfile, proxy, insecure, skipAll, restartAll, ignoreSha1)
		defer downloader.Close()
		downloader.URL = download.XcodeDlURL + "/" + choice
		downloader.Sha1 = sha1
		downloader.DestName = choice
		_, err = downloader.DoContext(cmd.Context())
		return err
	},
}
