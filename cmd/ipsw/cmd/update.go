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
	"archive/zip"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/dustin/go-humanize"
	"github.com/hashicorp/go-version"
	"github.com/spf13/cobra"
)

type releaseAsset struct {
	ID            int       `json:"id,omitempty"`
	Name          string    `json:"name,omitempty"`
	URL           string    `json:"url,omitempty"`
	DownloadURL   string    `json:"browser_download_url,omitempty"`
	Size          int       `json:"size,omitempty"`
	DownloadCount int       `json:"download_count,omitempty"`
	CreatedAt     time.Time `json:"created_at,omitempty"`
	UpdatedAt     time.Time `json:"updated_at,omitempty"`
}

func (a releaseAsset) String() string {
	return a.Name
}

type githubRelease struct {
	ID          int            `json:"id,omitempty"`
	URL         string         `json:"url,omitempty"`
	HtmlURL     string         `json:"html_url,omitempty"`
	Tag         string         `json:"tag_name,omitempty"`
	CreatedAt   time.Time      `json:"created_at,omitempty"`
	PublishedAt time.Time      `json:"published_at,omitempty"`
	Assets      []releaseAsset `json:"assets,omitempty"`
	Body        string         `json:"body,omitempty"`
}

type GithubReleases []githubRelease

func init() {
	rootCmd.AddCommand(updateCmd)

	updateCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	updateCmd.Flags().Bool("insecure", false, "do not verify ssl certs")
	updateCmd.Flags().Bool("detect", false, "detect my platform")
	updateCmd.Flags().Bool("replace", false, "overwrite current ipsw")
	// updateCmd.Flags().BoolP("yes", "y", false, "do not prompt user")

	updateCmd.Flags().StringP("platform", "p", "", "ipsw platform binary to update")
}

func queryGithub(proxy string, insecure bool) (GithubReleases, error) {

	var releases GithubReleases

	req, err := http.NewRequest("GET", "https://api.github.com/repos/blacktop/ipsw/releases", nil)
	if err != nil {
		return nil, fmt.Errorf("cannot create http request: %v", err)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           download.GetProxy(proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client failed to perform request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to connect to URL: %s", resp.Status)
	}

	document, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read github api JSON: %v", err)
	}

	if err := json.Unmarshal(document, &releases); err != nil {
		return nil, fmt.Errorf("failed to unmarshal the github api JSON: %v", err)
	}

	return releases, nil
}

// updateCmd represents the update command
var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Download an ipsw update if one exists",
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

		releases, err := queryGithub(proxy, insecure)
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

		var asset releaseAsset
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

		downloader := download.NewDownload(proxy, insecure, false)
		fname := strings.Replace(path.Base(asset.DownloadURL), ",", "_", -1)
		fname = filepath.Join(destPath, fname)
		if _, err := os.Stat(fname); os.IsNotExist(err) {
			log.WithFields(log.Fields{
				"version":        latestRelease.Tag,
				"published_at":   latestRelease.PublishedAt.Format("2006-01-02"),
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
