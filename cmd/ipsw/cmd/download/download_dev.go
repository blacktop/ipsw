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
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/caarlos0/ctrlc"
	"github.com/fatih/color"

	"github.com/blacktop/ipsw/internal/download"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DownloadCmd.AddCommand(downloadDevCmd)
	// Download behavior flags
	downloadDevCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	downloadDevCmd.Flags().Bool("insecure", false, "do not verify ssl certs")
	downloadDevCmd.Flags().Bool("skip-all", false, "always skip resumable IPSWs")
	downloadDevCmd.Flags().Bool("resume-all", false, "always resume resumable IPSWs")
	downloadDevCmd.Flags().Bool("restart-all", false, "always restart resumable IPSWs")
	downloadDevCmd.Flags().BoolP("remove-commas", "_", false, "replace commas in IPSW filename with underscores")
	// Auth flags
	downloadDevCmd.Flags().StringP("username", "u", "", "Apple Developer Portal username")
	downloadDevCmd.Flags().StringP("password", "p", "", "Apple Developer Portal password")
	downloadDevCmd.Flags().StringP("vault-password", "k", "", "Password to unlock credential vault (only for file vaults)")
	// Filter flags
	downloadDevCmd.Flags().StringP("version", "v", "", "iOS Version (i.e. 12.3.1)")
	downloadDevCmd.Flags().StringP("build", "b", "", "iOS BuildID (i.e. 16F203)")
	// Command-specific flags
	downloadDevCmd.Flags().StringArrayP("watch", "w", []string{}, "Developer portal group pattern to watch (i.e. '^iOS.*beta$')")
	downloadDevCmd.Flags().Bool("os", false, "Download '*OS' OSes/Apps")
	downloadDevCmd.Flags().Bool("profile", false, "Download Logging Profiles")
	downloadDevCmd.Flags().Bool("more", false, "Download 'More' OSes/Apps")
	downloadDevCmd.Flags().Bool("kdk", false, "Download KDK")
	downloadDevCmd.Flags().MarkHidden("kdk")
	downloadDevCmd.MarkFlagsMutuallyExclusive("os", "profile", "more", "kdk")
	downloadDevCmd.Flags().Int("page", 20, "Page size for file lists")
	downloadDevCmd.Flags().Bool("sms", false, "Prefer SMS Two-factor authentication")
	downloadDevCmd.Flags().Bool("json", false, "Output downloadable items as JSON")
	downloadDevCmd.Flags().Bool("pretty", false, "Pretty print JSON")
	downloadDevCmd.Flags().DurationP("timeout", "t", 5*time.Minute, "Timeout for watch attempts in minutes")
	downloadDevCmd.Flags().StringP("output", "o", "", "Folder to download files to")
	downloadDevCmd.MarkFlagDirname("output")
	// Bind persistent flags
	viper.BindPFlag("download.dev.proxy", downloadDevCmd.Flags().Lookup("proxy"))
	viper.BindPFlag("download.dev.insecure", downloadDevCmd.Flags().Lookup("insecure"))
	viper.BindPFlag("download.dev.skip-all", downloadDevCmd.Flags().Lookup("skip-all"))
	viper.BindPFlag("download.dev.resume-all", downloadDevCmd.Flags().Lookup("resume-all"))
	viper.BindPFlag("download.dev.restart-all", downloadDevCmd.Flags().Lookup("restart-all"))
	viper.BindPFlag("download.dev.remove-commas", downloadDevCmd.Flags().Lookup("remove-commas"))
	// Auth flags
	viper.BindPFlag("download.dev.username", downloadDevCmd.Flags().Lookup("username"))
	viper.BindPFlag("download.dev.password", downloadDevCmd.Flags().Lookup("password"))
	viper.BindPFlag("download.dev.vault-password", downloadDevCmd.Flags().Lookup("vault-password"))
	// Filter flags
	viper.BindPFlag("download.dev.version", downloadDevCmd.Flags().Lookup("version"))
	viper.BindPFlag("download.dev.build", downloadDevCmd.Flags().Lookup("build"))
	// Bind command-specific flags
	viper.BindPFlag("download.dev.watch", downloadDevCmd.Flags().Lookup("watch"))
	viper.BindPFlag("download.dev.os", downloadDevCmd.Flags().Lookup("os"))
	viper.BindPFlag("download.dev.profile", downloadDevCmd.Flags().Lookup("profile"))
	viper.BindPFlag("download.dev.more", downloadDevCmd.Flags().Lookup("more"))
	viper.BindPFlag("download.dev.page", downloadDevCmd.Flags().Lookup("page"))
	viper.BindPFlag("download.dev.sms", downloadDevCmd.Flags().Lookup("sms"))
	viper.BindPFlag("download.dev.json", downloadDevCmd.Flags().Lookup("json"))
	viper.BindPFlag("download.dev.pretty", downloadDevCmd.Flags().Lookup("pretty"))
	viper.BindPFlag("download.dev.kdk", downloadDevCmd.Flags().Lookup("kdk"))
	viper.BindPFlag("download.dev.timeout", downloadDevCmd.Flags().Lookup("timeout"))
	viper.BindPFlag("download.dev.output", downloadDevCmd.Flags().Lookup("output"))
	viper.BindPFlag("download.dev.vault-password", downloadDevCmd.Flags().Lookup("vault-password"))
}

// downloadDevCmd represents the dev command
var downloadDevCmd = &cobra.Command{
	Use:     "dev",
	Aliases: []string{"d", "developer"},
	Short:   "Download IPSWs (and more) from the Apple Developer Portal",
	Example: heredoc.Doc(`
		# Download all available OSes interactively
		❯ ipsw download dev --os

		# Download logging profiles as JSON
		❯ ipsw download dev --profile --json --pretty

		# Watch for new releases matching pattern
		❯ ipsw download dev --watch "^iOS.*beta$"

		# Download more items (Xcode, KDKs, etc.)
		❯ ipsw download dev --more --output ~/Downloads
	`),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// settings
		proxy := viper.GetString("download.dev.proxy")
		insecure := viper.GetBool("download.dev.insecure")
		skipAll := viper.GetBool("download.dev.skip-all")
		resumeAll := viper.GetBool("download.dev.resume-all")
		restartAll := viper.GetBool("download.dev.restart-all")
		removeCommas := viper.GetBool("download.dev.remove-commas")
		// flags
		watchList := viper.GetStringSlice("download.dev.watch")
		pageSize := viper.GetInt("download.dev.page")
		sms := viper.GetBool("download.dev.sms")
		asJSON := viper.GetBool("download.dev.json")
		prettyJSON := viper.GetBool("download.dev.pretty")
		output := viper.GetString("download.dev.output")
		// auth
		username := viper.GetString("download.dev.username")
		password := viper.GetString("download.dev.password")

		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get user home directory: %v", err)
		}

		app := download.NewDevPortal(&download.DevConfig{
			Proxy:         proxy,
			Insecure:      insecure,
			SkipAll:       skipAll,
			ResumeAll:     resumeAll,
			RestartAll:    restartAll,
			RemoveCommas:  removeCommas,
			PreferSMS:     sms,
			PageSize:      pageSize,
			WatchList:     watchList,
			ConfigDir:     filepath.Join(home, ".ipsw"),
			VaultPassword: viper.GetString("download.dev.vault-password"),
			Verbose:       viper.GetBool("verbose"),
		})

		if err := app.Init(); err != nil {
			return fmt.Errorf("failed to initialize app: %v", err)
		}

		if err := app.Login(username, password); err != nil {
			return fmt.Errorf("failed to login: %v", err)
		}

		if viper.GetBool("download.dev.kdk") {
			return app.DownloadKDK(viper.GetString("download.dev.version"), viper.GetString("download.dev.build"), output)
		}

		dlType := ""
		if viper.GetBool("download.dev.os") {
			dlType = "os"
		} else if viper.GetBool("download.dev.profile") {
			dlType = "profile"
		} else if viper.GetBool("download.dev.more") {
			dlType = "more"
		} else {
			prompt := &survey.Select{
				Message: "Choose a download type:",
				Options: []string{"OSes (iOS, macOS, tvOS...)", "Profiles (Logging)", "More (Xcode, KDKs...)"},
			}
			if err := survey.AskOne(prompt, &dlType); err != nil {
				if err == terminal.InterruptErr {
					log.Warn("Exiting...")
					return nil
				}
				return err
			}
			if strings.HasPrefix(dlType, "OSes") {
				dlType = "os"
			} else if strings.HasPrefix(dlType, "Profiles") {
				dlType = "profile"
			} else if strings.HasPrefix(dlType, "More") {
				dlType = "more"
			}
		}

		if len(watchList) > 0 {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			if err := ctrlc.Default.Run(ctx, func() error {
				if err := app.Watch(ctx, dlType, output, viper.GetDuration("download.dev.timeout")); err != nil {
					return fmt.Errorf("failed to watch: %v", err)
				}
				return nil
			}); err != nil {
				if errors.As(err, &ctrlc.ErrorCtrlC{}) {
					log.Warn("Exiting...")
					return nil
				} else {
					return fmt.Errorf("failed while watching: %v", err)
				}
			}
		}

		if asJSON {
			if dat, err := app.GetDownloadsAsJSON(dlType, prettyJSON); err != nil {
				return fmt.Errorf("failed to get downloads as JSON: %v", err)
			} else {
				if len(output) > 0 {
					fpath := filepath.Join(output, fmt.Sprintf("dev_portal_%s.json", dlType))
					log.Infof("Creating %s", fpath)
					if err := os.WriteFile(fpath, dat, 0660); err != nil {
						return fmt.Errorf("failed to write file %s: %v", fpath, err)
					}
				} else {
					fmt.Println(string(dat))
				}
			}
		} else {
			if err := app.DownloadPrompt(dlType, output); err != nil {
				return fmt.Errorf("failed to download: %v", err)
			}
		}
		return nil
	},
}
