//go:build !ios

/*
Copyright © 2018-2025 blacktop

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
	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/fatih/color"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DownloadCmd.AddCommand(downloadIpaCmd)
	// Download behavior flags
	downloadIpaCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	downloadIpaCmd.Flags().Bool("insecure", false, "do not verify ssl certs")
	// Command-specific flags
	downloadIpaCmd.Flags().Bool("sms", false, "Prefer SMS Two-factor authentication")
	downloadIpaCmd.Flags().Bool("search", false, "Search for app to download")
	downloadIpaCmd.Flags().StringP("output", "o", "", "Folder to download files to")
	downloadIpaCmd.MarkFlagDirname("output")
	downloadIpaCmd.Flags().StringP("store-front", "s", "US", "The country code for the App Store to download from")
	// Auth flags
	downloadIpaCmd.Flags().String("username", "", "Username for authentication")
	downloadIpaCmd.Flags().String("password", "", "Password for authentication")
	downloadIpaCmd.Flags().StringP("vault-password", "k", "", "Password to unlock credential vault (only for file vaults)")
	// downloadIpaCmd.Flags().StringP("keybag-plist", "p", "", "Path to the keybag plist file (includes kbsync)")
	// Bind persistent flags
	viper.BindPFlag("download.ipa.proxy", downloadIpaCmd.Flags().Lookup("proxy"))
	viper.BindPFlag("download.ipa.insecure", downloadIpaCmd.Flags().Lookup("insecure"))
	// Bind command-specific flags
	viper.BindPFlag("download.ipa.sms", downloadIpaCmd.Flags().Lookup("sms"))
	viper.BindPFlag("download.ipa.search", downloadIpaCmd.Flags().Lookup("search"))
	viper.BindPFlag("download.ipa.output", downloadIpaCmd.Flags().Lookup("output"))
	viper.BindPFlag("download.ipa.store-front", downloadIpaCmd.Flags().Lookup("store-front"))
	viper.BindPFlag("download.ipa.username", downloadIpaCmd.Flags().Lookup("username"))
	viper.BindPFlag("download.ipa.password", downloadIpaCmd.Flags().Lookup("password"))
	viper.BindPFlag("download.ipa.vault-password", downloadIpaCmd.Flags().Lookup("vault-password"))
	// viper.BindPFlag("download.ipa.keybag-plist", downloadIpaCmd.Flags().Lookup("keybag-plist"))
}

// downloadIpaCmd represents the dev command
var downloadIpaCmd = &cobra.Command{
	Use:     "ipa",
	Aliases: []string{"app"},
	Short:   "Download App Packages from the iOS App Store",
	Example: heredoc.Doc(`
		# Download specific app by bundle ID
		❯ ipsw download ipa com.zhiliaoapp.musically

		# Search for apps and download interactively
		❯ ipsw download ipa --search twitter

		# Download from different store front
		❯ ipsw download ipa --store-front UK com.zhiliaoapp.musically

		# Download to specific directory
		❯ ipsw download ipa --output ./apps com.zhiliaoapp.musically
	`),
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// settings
		proxy := viper.GetString("download.ipa.proxy")
		insecure := viper.GetBool("download.ipa.insecure")
		// flags
		sms := viper.GetBool("download.ipa.sms")
		output := viper.GetString("download.ipa.output")
		// auth
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
			VaultPassword: viper.GetString("download.ipa.vault-password"),
			StoreFront:    viper.GetString("download.ipa.store-front"),
			KeybagPlist:   viper.GetString("download.ipa.keybag-plist"),
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
					return nil
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
