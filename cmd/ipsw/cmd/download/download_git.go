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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DownloadCmd.AddCommand(gitCmd)

	gitCmd.Flags().StringP("product", "p", "", "macOS product to download (i.e. dyld)")
	gitCmd.Flags().StringP("output", "o", "", "Folder to download files to")
	gitCmd.Flags().StringP("api", "a", "", "Github API Token")
	gitCmd.Flags().Bool("json", false, "Output downloadable tar.gz URLs as JSON")
	gitCmd.Flags().Bool("webkit", false, "Get WebKit tags")
	gitCmd.MarkFlagDirname("output")
	gitCmd.SetHelpFunc(func(c *cobra.Command, s []string) {
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
	viper.BindPFlag("download.git.product", gitCmd.Flags().Lookup("product"))
	viper.BindPFlag("download.git.output", gitCmd.Flags().Lookup("output"))
	viper.BindPFlag("download.git.api", gitCmd.Flags().Lookup("api"))
	viper.BindPFlag("download.git.json", gitCmd.Flags().Lookup("json"))
	viper.BindPFlag("download.git.webkit", gitCmd.Flags().Lookup("webkit"))
}

// gitCmd represents the git command
var gitCmd = &cobra.Command{
	Use:           "git",
	Aliases:       []string{"g", "github"},
	Short:         "Download github.com/orgs/apple-oss-distributions tarballs",
	SilenceUsage:  false,
	SilenceErrors: false,
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
		downloadProduct := viper.GetString("download.git.product")
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

		var err error
		tags := make(map[string]download.GithubTag)

		if len(apiToken) == 0 {
			log.Info("Querying github.com/blacktop/ipsw/apple_meta/github/tag_links.json for repositories...")
			tags, err = download.GetPreprocessedAppleOssTags(proxy, insecure)
			if err != nil {
				return fmt.Errorf("failed to get tags from `ipsw` apple_meta: %w", err)
			}
		} else {
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
						os.MkdirAll(outputFolder, 0750)
						fpath := filepath.Join(outputFolder, "webkit_tags.json")
						log.Infof("Creating %s", fpath)
						if err := os.WriteFile(fpath, dat, 0660); err != nil {
							return fmt.Errorf("failed to write file: %v", err)
						}
					} else {
						fmt.Println(string(dat))
					}
				}
				return nil
			}

			log.Info("Querying github.com/orgs/apple-oss-distributions for repositories...")
			tags, err = download.AppleOssGraphQLTags(proxy, insecure, apiToken)
			if err != nil {
				return fmt.Errorf("failed to get tags from Github GraphQL API: %w", err)
			}

			if asJSON {
				dat, err := json.Marshal(tags)
				if err != nil {
					return fmt.Errorf("failed to marshal JSON: %v", err)
				}
				if len(outputFolder) > 0 {
					os.MkdirAll(outputFolder, 0750)
					fpath := filepath.Join(outputFolder, "tag_links.json")
					log.Infof("Creating %s", fpath)
					if err := os.WriteFile(fpath, dat, 0660); err != nil {
						return fmt.Errorf("failed to write file: %v", err)
					}
				} else {
					fmt.Println(string(dat))
				}
				return nil
			}
		}

		filteredTags := make(map[string]download.GithubTag)

		if len(downloadProduct) > 0 {
			if val, ok := tags[downloadProduct]; ok {
				filteredTags[downloadProduct] = val
			} else {
				return fmt.Errorf("product %s not found", downloadProduct)
			}
		} else {
			filteredTags = tags
		}

		for _, tag := range filteredTags {
			destName := getDestName(tag.TarURL, false)
			destName = filepath.Join(outputFolder, destName)

			if _, err := os.Stat(destName); os.IsNotExist(err) {
				log.WithFields(log.Fields{
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

				resp.Body.Close()

				if err := os.WriteFile(destName, document, 0660); err != nil {
					return fmt.Errorf("failed to write file %s: %v", destName, err)
				}
			} else {
				log.Warnf("file already exists: %s", destName)
			}
		}

		return nil
	},
}
