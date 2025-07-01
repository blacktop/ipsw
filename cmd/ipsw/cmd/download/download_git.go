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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DownloadCmd.AddCommand(downloadGitCmd)
	// Download behavior flags
	downloadGitCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	downloadGitCmd.Flags().Bool("insecure", false, "do not verify ssl certs")
	// Command-specific flags
	downloadGitCmd.Flags().StringP("product", "p", "", "macOS product to download (i.e. dyld)")
	downloadGitCmd.Flags().Bool("latest", false, "Get ONLY latest tag")
	downloadGitCmd.Flags().StringP("output", "o", "", "Folder to download files to")
	downloadGitCmd.MarkFlagDirname("output")
	downloadGitCmd.Flags().StringP("api", "a", "", "Github API Token")
	downloadGitCmd.Flags().Bool("json", false, "Output downloadable tar.gz URLs as JSON")
	downloadGitCmd.Flags().Bool("webkit", false, "Get WebKit tags")
	// Bind persistent flags
	viper.BindPFlag("download.git.proxy", downloadGitCmd.Flags().Lookup("proxy"))
	viper.BindPFlag("download.git.insecure", downloadGitCmd.Flags().Lookup("insecure"))
	// Bind command-specific flags
	viper.BindPFlag("download.git.product", downloadGitCmd.Flags().Lookup("product"))
	viper.BindPFlag("download.git.latest", downloadGitCmd.Flags().Lookup("latest"))
	viper.BindPFlag("download.git.output", downloadGitCmd.Flags().Lookup("output"))
	viper.BindPFlag("download.git.api", downloadGitCmd.Flags().Lookup("api"))
	viper.BindPFlag("download.git.json", downloadGitCmd.Flags().Lookup("json"))
	viper.BindPFlag("download.git.webkit", downloadGitCmd.Flags().Lookup("webkit"))
}

// downloadGitCmd represents the git command
var downloadGitCmd = &cobra.Command{
	Use:     "git",
	Aliases: []string{"g", "github"},
	Short:   "Download github.com/orgs/apple-oss-distributions tarballs",
	Example: heredoc.Doc(`
		# Download latest dyld source tarballs
		❯ ipsw download git --product dyld --latest

		# Get all available tarballs as JSON
		❯ ipsw download git --json --output ~/sources

		# Download WebKit tags (not Apple OSS)
		❯ ipsw download git --webkit --json

		# Download specific product with API token
		❯ ipsw download git --product xnu --api YOUR_TOKEN
	`),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) (err error) {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// settings
		proxy := viper.GetString("download.git.proxy")
		insecure := viper.GetBool("download.git.insecure")
		// flags
		downloadProduct := viper.GetString("download.git.product")
		latest := viper.GetBool("download.git.latest")
		outputFolder := viper.GetString("download.git.output")
		apiToken := viper.GetString("download.git.api")
		asJSON := viper.GetBool("download.git.json")

		if len(apiToken) == 0 {
			if val, ok := os.LookupEnv("GITHUB_TOKEN"); ok {
				apiToken = val
			} else {
				if val, ok := os.LookupEnv("GITHUB_API_TOKEN"); ok {
					apiToken = val
				}
			}
		}

		if viper.GetBool("download.git.webkit") { // only download WebKit tags JSON
			log.Info("Querying github.com/WebKit/WebKit for tags...")
			wkTags, err := download.WebKitGraphQLTags(proxy, insecure, apiToken)
			if err != nil {
				return fmt.Errorf("failed to get tags from Github GraphQL API: %w", err)
			}
			if asJSON {
				dat, err := json.Marshal(wkTags)
				if err != nil {
					return fmt.Errorf("failed to marshal JSON: %v", err)
				}
				if len(outputFolder) > 0 {
					if err := os.MkdirAll(outputFolder, 0750); err != nil {
						return fmt.Errorf("failed to create output folder %s: %v", outputFolder, err)
					}
					fpath := filepath.Join(outputFolder, "webkit_tags.json")
					log.Infof("Creating %s", fpath)
					if err := os.WriteFile(fpath, dat, 0644); err != nil {
						return fmt.Errorf("failed to write file %s: %v", fpath, err)
					}
				} else {
					fmt.Println(string(dat))
				}
			}
			return nil
		}
		if downloadProduct == "" {
			log.Info("Querying github.com/orgs/apple-oss-distributions for repositories...")
		} else {
			log.Infof("Querying github.com/orgs/apple-oss-distributions for %s...", downloadProduct)
		}
		limit := 20
		if latest {
			limit = 1
		}
		tags, err := download.AppleOssGraphQLTags(downloadProduct, limit, proxy, insecure, apiToken)
		if err != nil {
			return fmt.Errorf("failed to get tags from Github GraphQL API: %w", err)
		}

		if asJSON {
			dat, err := json.Marshal(tags)
			if err != nil {
				return fmt.Errorf("failed to marshal JSON: %v", err)
			}
			if len(outputFolder) > 0 {
				if err := os.MkdirAll(outputFolder, 0750); err != nil {
					return fmt.Errorf("failed to create output folder %s: %v", outputFolder, err)
				}
				fpath := filepath.Join(outputFolder, "tag_links.json")
				log.Infof("Creating %s", fpath)
				if err := os.WriteFile(fpath, dat, 0644); err != nil {
					return fmt.Errorf("failed to write file %s: %v", fpath, err)
				}
			} else {
				fmt.Println(string(dat))
			}
			return nil
		}

		for repo, commits := range tags {
			for _, tag := range commits {
				destName := getDestName(tag.TarURL, false)
				if len(outputFolder) > 0 {
					if err := os.MkdirAll(outputFolder, 0750); err != nil {
						return fmt.Errorf("failed to create output folder %s: %v", outputFolder, err)
					}
				}
				destName = filepath.Join(outputFolder, destName)

				if _, err := os.Stat(destName); os.IsNotExist(err) {
					log.WithFields(log.Fields{
						"repo": repo,
						"file": destName,
					}).Info("Downloading")

					req, err := http.NewRequest("GET", tag.TarURL, nil)
					if err != nil {
						return fmt.Errorf("cannot create http request: %v", err)
					}

					client := &http.Client{
						Transport: &http.Transport{
							Proxy:           download.GetProxy(proxy),
							TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
						},
					}

					resp, err := client.Do(req)
					if err != nil {
						return fmt.Errorf("client failed to perform request: %v", err)
					}
					defer resp.Body.Close()

					if resp.StatusCode != 200 {
						return fmt.Errorf("failed to connect to URL: %s", resp.Status)
					}

					document, err := io.ReadAll(resp.Body)
					if err != nil {
						return fmt.Errorf("failed to read remote tarfile data: %v", err)
					}

					if err := os.WriteFile(destName, document, 0644); err != nil {
						return fmt.Errorf("failed to write file %s: %v", destName, err)
					}
				} else {
					log.Warnf("file already exists: %s", destName)
				}
			}
		}

		return nil
	},
}
