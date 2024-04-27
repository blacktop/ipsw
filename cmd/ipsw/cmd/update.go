/*
Copyright © 2018-2024 blacktop

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
	"archive/zip"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/dustin/go-humanize"
	"github.com/hashicorp/go-version"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(updateCmd)

	updateCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	updateCmd.Flags().Bool("insecure", false, "do not verify ssl certs")
	updateCmd.Flags().Bool("detect", false, "detect my platform")
	updateCmd.Flags().Bool("replace", false, "overwrite current ipsw")
	// updateCmd.Flags().BoolP("yes", "y", false, "do not prompt user")
	updateCmd.Flags().StringP("api", "a", "", "Github API Token (incase you get rate limited)")

	updateCmd.Flags().StringP("platform", "p", "", "ipsw platform binary to update")
}

// updateCmd represents the update command
var updateCmd = &cobra.Command{
	Use:           "update",
	Aliases:       []string{"u"},
	Short:         "Download an ipsw update if one exists",
	SilenceUsage:  true,
	SilenceErrors: true,
	Hidden:        true, // NOTE: this is hidden because I believe it is no longer needed
	// (but in case others are using it in automated scripts etc I'll leave it in for now)
	Example: `# Grab an update for your platform
❯ ipsw update --detect
# Grab an update for another platform
❯ ipsw update --platform windows_x86_64
# Grab an update for your platform and overwrite the current one
❯ ipsw update --detect --replace`,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		proxy, _ := cmd.Flags().GetString("proxy")
		insecure, _ := cmd.Flags().GetBool("insecure")
		// confirm, _ := cmd.Flags().GetBool("yes")
		replace, _ := cmd.Flags().GetBool("replace")

		platform, _ := cmd.Flags().GetString("platform")
		detectPlatform, _ := cmd.Flags().GetBool("detect")
		apiToken, _ := cmd.Flags().GetString("api")

		if detectPlatform {
			os := runtime.GOOS
			switch os {
			case "windows":
				os = "windows"
			case "darwin":
				os = "macOS"
			case "linux":
				os = "linux"
			default:
				return fmt.Errorf("unsupported OS found: %s", os)
			}
			arch := runtime.GOARCH
			switch arch {
			case "arm64":
				arch = "arm64"
			case "amd64":
				arch = "x86_64"
			default:
				return fmt.Errorf("unsupported ARCH found: %s", arch)
			}
			platform = fmt.Sprintf("%s_%s", os, arch)
		}

		var destPath string
		if len(args) > 0 {
			destPath = filepath.Clean(args[0])
		}

		if len(apiToken) == 0 {
			if val, ok := os.LookupEnv("GITHUB_TOKEN"); ok {
				apiToken = val
			} else {
				if val, ok := os.LookupEnv("GITHUB_API_TOKEN"); ok {
					apiToken = val
				}
			}
		}

		releases, err := download.GetGithubIPSWReleases(proxy, insecure, apiToken)
		if err != nil {
			return err
		}

		if len(releases) == 0 {
			return fmt.Errorf("github returned 0 release info")
		}

		latestRelease := releases[0]

		if len(platform) == 0 || detectPlatform {
			currentVersion, err := version.NewVersion(AppVersion)
			if err != nil {
				return err
			}
			latestVersion, err := version.NewVersion(strings.TrimPrefix(latestRelease.Tag, "v"))
			if err != nil {
				return err
			}

			if currentVersion.Equal(latestVersion) {
				log.Info("you already have the latest version")
				return nil
			}
		}

		var asset download.GithubReleaseAsset
		var assetFiles []string

		for _, a := range latestRelease.Assets {
			assetFiles = append(assetFiles, a.Name)
		}

		if len(platform) == 0 {
			if len(latestRelease.Assets) > 0 {
				choice := 0
				prompt := &survey.Select{
					Message: "Select the file you would like to download:",
					Options: assetFiles,
				}
				survey.AskOne(prompt, &choice)
				asset = latestRelease.Assets[choice]
			} else {
				return fmt.Errorf("release %s contained 0 assets", latestRelease.Tag)
			}
		} else {
			found := false
			for _, a := range latestRelease.Assets {
				if strings.Contains(a.Name, platform) {
					asset = a
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("supplied platform %s did not match any of the release files", platform)
			}
		}

		downloader := download.NewDownload(proxy, insecure, false, false, false, false, Verbose)
		fname := strings.Replace(path.Base(asset.DownloadURL), ",", "_", -1)
		fname = filepath.Join(destPath, fname)
		if _, err := os.Stat(fname); os.IsNotExist(err) {
			log.WithFields(log.Fields{
				"version":        latestRelease.Tag,
				"published_at":   latestRelease.PublishedAt.Format("02Jan2006 15:04:05"),
				"size":           humanize.Bytes(uint64(asset.Size)),
				"download_count": asset.DownloadCount,
			}).Info("Getting Update")
			// download file
			downloader.URL = asset.DownloadURL
			downloader.DestName = fname
			err = downloader.Do()
			if err != nil {
				return fmt.Errorf("failed to download file: %v", err)
			}
			fmt.Println()
			fmt.Println(latestRelease.Body)

			if replace {
				currentIpswDir, err := filepath.Abs(filepath.Dir(os.Args[0]))
				if err != nil {
					return err
				}
				fmt.Println(currentIpswDir)
				tempDir := os.TempDir()
				if filepath.Ext(fname) == ".gz" {
					if err := utils.UnTarGz(fname, tempDir); err != nil {
						return err
					}
					if err := os.Rename(filepath.Join(tempDir, "ipsw"), filepath.Join(currentIpswDir, "ipsw")); err != nil {
						return err
					}
				} else {
					utils.Unzip(fname, tempDir, func(f *zip.File) bool {
						return strings.EqualFold(f.Name, "ipsw.exe")
					})
					if err := os.Rename(filepath.Join(tempDir, "ipsw.exe"), filepath.Join(currentIpswDir, "ipsw.exe")); err != nil {
						return err
					}
				}
				// cleanup
				os.Remove(fname)
			}
		} else {
			log.Warnf("ipsw update already exists: %s", fname)
		}

		return nil
	},
}
