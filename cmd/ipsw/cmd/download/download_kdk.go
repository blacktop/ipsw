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
	"os"
	"path"
	"path/filepath"
	"sort"

	"github.com/AlecAivazis/survey/v2"
	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

func init() {
	DownloadCmd.AddCommand(downloadKdkCmd)
	// Download behavior flags
	downloadKdkCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	downloadKdkCmd.Flags().Bool("insecure", false, "do not verify ssl certs")
	downloadKdkCmd.Flags().Bool("skip-all", false, "continue past files locked by another download process")
	downloadKdkCmd.Flags().Bool("ignore-sha1", false, "skip checksum verification")
	downloadKdkCmd.Flags().Bool("restart-all", false, "always restart resumable IPSWs")
	// Command-specific flags
	downloadKdkCmd.Flags().Bool("host", false, "Download KDK for current host OS")
	downloadKdkCmd.Flags().StringP("build", "b", "", "Download KDK for build")
	downloadKdkCmd.Flags().BoolP("latest", "l", false, "Download latest KDK")
	downloadKdkCmd.Flags().BoolP("all", "a", false, "Download all KDKs")
	downloadKdkCmd.Flags().BoolP("install", "i", false, "Install KDK after download")
	downloadKdkCmd.Flags().Bool("clean", false, "Delete downloaded KDK after successful installation")
	downloadKdkCmd.Flags().StringP("output", "o", "", "Folder to download files to")
	downloadKdkCmd.MarkFlagDirname("output")
	downloadKdkCmd.MarkFlagsMutuallyExclusive("host", "build", "latest", "all")
	// Bind persistent flags
	viper.BindPFlag("download.kdk.proxy", downloadKdkCmd.Flags().Lookup("proxy"))
	viper.BindPFlag("download.kdk.insecure", downloadKdkCmd.Flags().Lookup("insecure"))
	viper.BindPFlag("download.kdk.skip-all", downloadKdkCmd.Flags().Lookup("skip-all"))
	viper.BindPFlag("download.kdk.ignore-sha1", downloadKdkCmd.Flags().Lookup("ignore-sha1"))
	viper.BindPFlag("download.kdk.restart-all", downloadKdkCmd.Flags().Lookup("restart-all"))
	// Bind command-specific flags
	viper.BindPFlag("download.kdk.host", downloadKdkCmd.Flags().Lookup("host"))
	viper.BindPFlag("download.kdk.build", downloadKdkCmd.Flags().Lookup("build"))
	viper.BindPFlag("download.kdk.latest", downloadKdkCmd.Flags().Lookup("latest"))
	viper.BindPFlag("download.kdk.all", downloadKdkCmd.Flags().Lookup("all"))
	viper.BindPFlag("download.kdk.install", downloadKdkCmd.Flags().Lookup("install"))
	viper.BindPFlag("download.kdk.clean", downloadKdkCmd.Flags().Lookup("clean"))
	viper.BindPFlag("download.kdk.output", downloadKdkCmd.Flags().Lookup("output"))
}

// downloadKdkCmd represents the kdk command
var downloadKdkCmd = &cobra.Command{
	Use:   "kdk",
	Short: "Download KDKs",
	Long: "Download KDKs. Without a selector, choose a KDK interactively.\n" +
		"Unattended use requires --host, --build, --latest, or --all.\n" +
		"After a successful --install, interactive sessions offer to delete the downloaded file.\n" +
		"Use --install --clean to delete it without prompting.",
	Example: heredoc.Doc(`
		# Download KDK for current host OS
		❯ ipsw download kdk --host

		# Download KDK for specific build
		❯ ipsw download kdk --build 20G75

		# Download latest KDK and install
		❯ ipsw download kdk --latest --install

		# Download, install, and delete the latest KDK installer
		❯ ipsw download kdk --latest --install --clean

		# Download all available KDKs
		❯ ipsw download kdk --all
	`),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		// settings
		proxy := viper.GetString("download.kdk.proxy")
		insecure := viper.GetBool("download.kdk.insecure")
		skipAll := viper.GetBool("download.kdk.skip-all")
		ignoreSha1 := viper.GetBool("download.kdk.ignore-sha1")
		restartAll := viper.GetBool("download.kdk.restart-all")
		// flags
		forHost := viper.GetBool("download.kdk.host")
		forBuild := viper.GetString("download.kdk.build")
		latest := viper.GetBool("download.kdk.latest")
		all := viper.GetBool("download.kdk.all")
		install := viper.GetBool("download.kdk.install")
		clean := viper.GetBool("download.kdk.clean")
		output := viper.GetString("download.kdk.output")
		if clean && !install {
			return fmt.Errorf("--clean requires --install")
		}
		if !forHost && forBuild == "" && !latest && !all &&
			(!term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd()))) {
			return fmt.Errorf("KDK selection requires an interactive terminal; use --host, --build, --latest, or --all")
		}

		kdks, err := download.ListKDKs()
		if err != nil {
			return err
		}
		if len(kdks) == 0 {
			return fmt.Errorf("no KDKs available")
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
			if err := survey.AskOne(prompt, &choice); err != nil {
				return fmt.Errorf("KDK selection failed (use --host, --build, --latest, or --all for unattended use): %w", err)
			}

			for _, kdk := range kdks {
				if kdk.Name == choice {
					dlKDKs = append(dlKDKs, kdk)
					break
				}
			}
		}
		if len(dlKDKs) == 0 {
			return fmt.Errorf("no KDK selected")
		}

		if len(dlKDKs) > 1 && install {
			log.Warn("Installing multiple KDKs")
		}

		downloader := download.NewDownloadWithProfile(
			download.AppleCDNProfile, proxy, insecure, skipAll, restartAll, ignoreSha1)
		defer downloader.Close()
		for _, kdk := range dlKDKs {
			destName := path.Base(kdk.URL)
			if len(output) > 0 {
				destName = filepath.Join(filepath.Clean(output), path.Base(kdk.URL))
			}
			if err := os.MkdirAll(filepath.Dir(destName), 0755); err != nil {
				return fmt.Errorf("failed to create directory: %v", err)
			}

			skippedLocked := false
			if _, err := os.Stat(destName); os.IsNotExist(err) {
				log.Infof("Downloading to %s...", destName)
				status, err := downloader.DoRequestContext(cmd.Context(), &download.FileRequest{
					URL:      kdk.URL,
					SHA256:   kdk.Sha256Sum,
					DestName: destName,
				})
				if err != nil {
					return err
				}
				skippedLocked = status != download.Downloaded
			} else {
				log.Warnf("File already exists: %s", destName)
			}

			if install {
				if skippedLocked {
					log.Warnf("Skipping installation while %s is being downloaded by another process", destName)
					continue
				}
				if err := installKDKDownload(destName, clean,
					term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stderr.Fd())),
					utils.InstallKDK,
					func(prompt *survey.Confirm, answer *bool) error {
						return survey.AskOne(prompt, answer, survey.WithStdio(os.Stdin, os.Stderr, os.Stderr))
					}); err != nil {
					return err
				}
			}
		}

		return nil
	},
}

func installKDKDownload(destName string, clean, interactive bool, install func(string) error, ask func(*survey.Confirm, *bool) error) error {
	log.Infof("Installing %s...", destName)
	if err := install(destName); err != nil {
		return err
	}
	remove := clean
	if !remove && interactive {
		if err := ask(&survey.Confirm{
			Message: fmt.Sprintf("Delete downloaded KDK %s?", destName),
		}, &remove); err != nil {
			return fmt.Errorf("keeping %s: cleanup confirmation failed: %w", destName, err)
		}
	}
	if !remove {
		return nil
	}
	if err := os.Remove(destName); err != nil {
		return fmt.Errorf("failed to delete %s: %w", destName, err)
	}
	log.Infof("Deleted %s", destName)
	return nil
}
