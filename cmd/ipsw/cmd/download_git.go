/*
Copyright © 2022 blacktop

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
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	downloadCmd.AddCommand(gitCmd)

	gitCmd.Flags().StringP("product", "p", "", "macOS product to download (i.e. dyld)")
	gitCmd.Flags().StringP("output", "o", "", "Folder to download files to")
	gitCmd.Flags().StringP("api", "a", "", "Github API Token")
	gitCmd.Flags().Bool("json", false, "Output downloadable tar.gz URLs as JSON")
	viper.BindPFlag("download.git.product", gitCmd.Flags().Lookup("product"))
	viper.BindPFlag("download.git.output", gitCmd.Flags().Lookup("output"))
	viper.BindPFlag("download.git.api", gitCmd.Flags().Lookup("api"))
	viper.BindPFlag("download.git.json", gitCmd.Flags().Lookup("json"))
}

// gitCmd represents the git command
var gitCmd = &cobra.Command{
	Use:           "git",
	Short:         "Download github.com/orgs/apple-oss-distributions tarballs",
	SilenceUsage:  false,
	SilenceErrors: false,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

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
			log.Info("Querying github.com/orgs/apple-oss-distributions for repositories...")
			tags, err = download.AppleOssGraphQLTags(proxy, insecure, apiToken)
			if err != nil {
				return fmt.Errorf("failed to get tags from `ipsw` apple_meta: %w", err)
			}

			if asJSON {
				dat, err := json.Marshal(tags)
				if err != nil {
					return fmt.Errorf("failed to marshal JSON: %v", err)
				}
				if len(outputFolder) > 0 {
					os.MkdirAll(outputFolder, os.ModePerm)
					fpath := filepath.Join(outputFolder, "tag_links.json")
					log.Infof("Creating %s", fpath)
					if err := ioutil.WriteFile(fpath, dat, 0755); err != nil {
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
				// download file
				downloader := download.NewDownload(proxy, insecure, false, false, false, false, false)
				downloader.URL = tag.TarURL
				downloader.DestName = destName

				err = downloader.Do()
				if err != nil {
					return fmt.Errorf("failed to download file: %v", err)
				}
			} else {
				log.Warnf("file already exists: %s", destName)
			}
		}

		return nil
	},
}
