//go:build !ios

/*
Copyright © 2018-2023 blacktop

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

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/fatih/color"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	ipaCmd.Flags().Bool("sms", false, "Prefer SMS Two-factor authentication")
	ipaCmd.Flags().Bool("search", false, "Search for app to download")
	ipaCmd.Flags().StringP("output", "o", "", "Folder to download files to")
	ipaCmd.Flags().StringP("store-front", "s", "US", "The country code for the App Store to download from")
	ipaCmd.Flags().StringP("vault-password", "k", "", "Password to unlock credential vault (only for file vaults)")
	ipaCmd.MarkFlagDirname("output")
	viper.BindPFlag("download.ipa.sms", ipaCmd.Flags().Lookup("sms"))
	viper.BindPFlag("download.ipa.search", ipaCmd.Flags().Lookup("search"))
	viper.BindPFlag("download.ipa.output", ipaCmd.Flags().Lookup("output"))
	viper.BindPFlag("download.ipa.store-front", ipaCmd.Flags().Lookup("store-front"))
	viper.BindPFlag("download.ipa.vault-password", ipaCmd.Flags().Lookup("vault-password"))
	ipaCmd.SetHelpFunc(func(c *cobra.Command, s []string) {
		DownloadCmd.PersistentFlags().MarkHidden("white-list")
		DownloadCmd.PersistentFlags().MarkHidden("black-list")
		DownloadCmd.PersistentFlags().MarkHidden("device")
		DownloadCmd.PersistentFlags().MarkHidden("model")
		DownloadCmd.PersistentFlags().MarkHidden("version")
		DownloadCmd.PersistentFlags().MarkHidden("build")
		DownloadCmd.PersistentFlags().MarkHidden("confirm")
		DownloadCmd.PersistentFlags().MarkHidden("skip-all")
		DownloadCmd.PersistentFlags().MarkHidden("resume-all")
		DownloadCmd.PersistentFlags().MarkHidden("restart-all")
		DownloadCmd.PersistentFlags().MarkHidden("remove-commas")
		c.Parent().HelpFunc()(c, s)
	})
	DownloadCmd.AddCommand(ipaCmd)
}

// ipaCmd represents the dev command
var ipaCmd = &cobra.Command{
	Use:           "ipa",
	Aliases:       []string{"app"},
	Short:         "Download App Packages from the iOS App Store",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  false,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		viper.BindPFlag("download.proxy", cmd.Flags().Lookup("proxy"))
		viper.BindPFlag("download.insecure", cmd.Flags().Lookup("insecure"))

		// settings
		proxy := viper.GetString("download.proxy")
		insecure := viper.GetBool("download.insecure")
		// flags
		sms := viper.GetBool("download.ipa.sms")
		output := viper.GetString("download.ipa.output")

		username := viper.GetString("download.ipa.username")
		password := viper.GetString("download.ipa.password")

		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get user home directory: %v", err)
		}

		as := download.NewAppStore(&download.AppStoreConfig{
			Proxy:         proxy,
			Insecure:      insecure,
			PreferSMS:     sms,
			ConfigDir:     filepath.Join(home, ".ipsw"),
			VaultPassword: viper.GetString("download.dev.vault-password"),
			StoreFront:    viper.GetString("download.ipa.store-front"),
			Verbose:       viper.GetBool("verbose"),
		})

		if err := as.Init(); err != nil {
			return fmt.Errorf("failed to initialize App Store: %v", err)
		}

		if err := as.Login(username, password); err != nil {
			return fmt.Errorf("failed to login to App Store: %v", err)
		}

		if viper.GetBool("download.ipa.search") {
			apps, err := as.Search(args[0], download.AppStoreSearchLimit)
			if err != nil {
				return fmt.Errorf("failed to search App Store: %v", err)
			}

			var choices []string
			for _, app := range apps {
				choices = append(choices, app.Name)
			}

			dfiles := []int{}
			prompt := &survey.MultiSelect{
				Message:  "Select what app(s) to download:",
				Options:  choices,
				PageSize: 20,
			}
			if err := survey.AskOne(prompt, &dfiles); err != nil {
				if err == terminal.InterruptErr {
					log.Warn("Exiting...")
					os.Exit(0)
				}
				return err
			}

			for _, df := range dfiles {
				if err := as.Download(apps[df].BundleID, output); err != nil {
					return fmt.Errorf("failed to download app %s: %v", apps[df].Name, err)
				}
			}

			return nil
		}

		return as.Download(args[0], output)
	},
}
