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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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
	viper.BindPFlag("download.git.product", gitCmd.Flags().Lookup("product"))
	viper.BindPFlag("download.git.output", gitCmd.Flags().Lookup("output"))
	viper.BindPFlag("download.git.api", gitCmd.Flags().Lookup("api"))
}

const githubApiURL = "https://api.github.com/orgs/apple-oss-distributions/repos?sort=updated&per_page=100"

type githubRepo struct {
	ID          int       `json:"id,omitempty"`
	URL         string    `json:"html_url,omitempty"`
	ReleasesURL string    `json:"releases_url,omitempty"`
	ArchiveURL  string    `json:"archive_url,omitempty"`
	TagsURL     string    `json:"tags_url,omitempty"`
	Name        string    `json:"name,omitempty"`
	Description string    `json:"description,omitempty"`
	FullName    string    `json:"full_name,omitempty"`
	Tag         string    `json:"tag_name,omitempty"`
	PublishedAt time.Time `json:"published_at,omitempty"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
}

type pageInfo struct {
	NextPage      int
	PrevPage      int
	FirstPage     int
	LastPage      int
	NextPageToken string
	Cursor        string
	Before        string
	After         string
}

type GithubRepos []githubRepo

type commit struct {
	SHA string `json:"sha,omitempty"`
	URL string `json:"url,omitempty"`
}

type githubTag struct {
	Name   string `json:"name,omitempty"`
	TarURL string `json:"tarball_url,omitempty"`
	ZipURL string `json:"zipball_url,omitempty"`
	Commit commit `json:"commit,omitempty"`
}

type GithubTags []githubTag

func queryAppleGithubRepo(prod, proxy string, insecure bool, api string) (*githubRepo, error) {
	var repo githubRepo
	req, err := http.NewRequest("GET", "https://api.github.com/repos/apple-oss-distributions/"+prod, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot create http request: %v", err)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	if len(api) > 0 {
		req.Header.Add("Authorization", "token "+api)
	}

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

	if err := json.Unmarshal(document, &repo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal the github api JSON: %v", err)
	}

	return &repo, nil
}

func queryAppleGithubRepos(proxy string, insecure bool, api string) (GithubRepos, error) {
	var resp *http.Response
	var page GithubRepos
	var repos GithubRepos

	req, err := http.NewRequest("GET", githubApiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot create http request: %v", err)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	if len(api) > 0 {
		req.Header.Add("Authorization", "token "+api)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           download.GetProxy(proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
	}

	resp, err = client.Do(req)
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

	if err := json.Unmarshal(document, &page); err != nil {
		return nil, fmt.Errorf("failed to unmarshal the github api JSON: %v", err)
	}

	repos = append(repos, page...)

	link := populatePageValues(resp)

	for link.NextPage > 0 {
		req, err := http.NewRequest("GET", fmt.Sprintf("%s&page=%d", githubApiURL, link.NextPage), nil)
		if err != nil {
			return nil, fmt.Errorf("cannot create http request: %v", err)
		}
		req.Header.Set("Accept", "application/vnd.github.v3+json")

		resp, err = client.Do(req)
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

		if err := json.Unmarshal(document, &page); err != nil {
			return nil, fmt.Errorf("failed to unmarshal the github api JSON: %v", err)
		}

		repos = append(repos, page...)

		link = populatePageValues(resp)
	}

	return repos, nil
}

// credit - https://github.com/google/go-github/blob/a842efca6534c3a0f6822cd633bcb0891f787a4b/github/github.go#L508
func populatePageValues(r *http.Response) pageInfo {
	var pinfo pageInfo
	if links, ok := r.Header["Link"]; ok && len(links) > 0 {
		for _, link := range strings.Split(links[0], ",") {
			segments := strings.Split(strings.TrimSpace(link), ";")

			// link must at least have href and rel
			if len(segments) < 2 {
				continue
			}

			// ensure href is properly formatted
			if !strings.HasPrefix(segments[0], "<") || !strings.HasSuffix(segments[0], ">") {
				continue
			}

			// try to pull out page parameter
			url, err := url.Parse(segments[0][1 : len(segments[0])-1])
			if err != nil {
				continue
			}

			q := url.Query()

			if cursor := q.Get("cursor"); cursor != "" {
				for _, segment := range segments[1:] {
					switch strings.TrimSpace(segment) {
					case `rel="next"`:
						pinfo.Cursor = cursor
					}
				}

				continue
			}

			page := q.Get("page")
			since := q.Get("since")
			before := q.Get("before")
			after := q.Get("after")

			if page == "" && before == "" && after == "" && since == "" {
				continue
			}

			if since != "" && page == "" {
				page = since
			}

			for _, segment := range segments[1:] {
				switch strings.TrimSpace(segment) {
				case `rel="next"`:
					if pinfo.NextPage, err = strconv.Atoi(page); err != nil {
						pinfo.NextPageToken = page
					}
					pinfo.After = after
				case `rel="prev"`:
					pinfo.PrevPage, _ = strconv.Atoi(page)
					pinfo.Before = before
				case `rel="first"`:
					pinfo.FirstPage, _ = strconv.Atoi(page)
				case `rel="last"`:
					pinfo.LastPage, _ = strconv.Atoi(page)
				}
			}
		}
	}

	return pinfo
}

func queryAppleGithubTags(url, proxy string, insecure bool, api string) (GithubTags, error) {

	var tags GithubTags

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot create http request: %v", err)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	if len(api) > 0 {
		req.Header.Add("Authorization", "token "+api)
	}

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

	if err := json.Unmarshal(document, &tags); err != nil {
		return nil, fmt.Errorf("failed to unmarshal the github api JSON: %v", err)
	}

	return tags, nil
}

// gitCmd represents the git command
var gitCmd = &cobra.Command{
	Use:           "git",
	Short:         "Download github.com/orgs/apple-oss-distributions tarballs",
	SilenceUsage:  false,
	SilenceErrors: false,
	RunE: func(cmd *cobra.Command, args []string) error {
		var err error
		var repos GithubRepos

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

		if len(apiToken) == 0 {
			if val, ok := os.LookupEnv("GITHUB_TOKEN"); ok {
				apiToken = val
			} else {
				if val, ok := os.LookupEnv("GITHUB_API_TOKEN"); ok {
					apiToken = val
				}
			}
		}

		if len(downloadProduct) == 0 {
			log.Info("Querying github.com/orgs/apple-oss-distributions for repositories...")
			repos, err = queryAppleGithubRepos(proxy, insecure, apiToken)
			if err != nil {
				return err
			}

			if len(repos) == 0 {
				return fmt.Errorf("no repos found")
			}
		} else {
			repo, err := queryAppleGithubRepo(downloadProduct, proxy, insecure, apiToken)
			if err != nil {
				return err
			}
			repos = append(repos, *repo)
		}

		for _, repo := range repos {
			tags, err := queryAppleGithubTags(strings.TrimSuffix(repo.TagsURL, "{/id}"), proxy, insecure, apiToken)
			if err != nil {
				return err
			}

			if len(tags) == 0 {
				log.Warnf("no tags found for repo %s", repo.FullName)
				continue
			}

			latestTag := tags[0]

			tarURL := fmt.Sprintf("https://github.com/apple-oss-distributions/%s/archive/refs/tags/%s.tar.gz", repo.Name, latestTag.Name)

			destName := getDestName(tarURL, false)
			destName = filepath.Join(outputFolder, destName)

			if _, err := os.Stat(destName); os.IsNotExist(err) {
				log.WithFields(log.Fields{
					"file": destName,
				}).Info("Downloading")
				// download file
				downloader := download.NewDownload(proxy, insecure, false, false, false, false)
				downloader.URL = tarURL
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
