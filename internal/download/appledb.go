package download

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/blacktop/ipsw/internal/utils"
)

const (
	// AppleDBRepoURL is the URL to the AppleDB github repo
	AppleDBRepoURL = "https://github.com/littlebyteorg/appledb"
	ApiContentsURL = "https://api.github.com/repos/littlebyteorg/appledb/contents/"
)

// GithubContentsResponse is the response from the GET /repos/{owner}/{repo}/contents/{path} github api
type GithubContentsResponse struct {
	Type        string `json:"type"`
	Encoding    string `json:"encoding"`
	Size        int    `json:"size"`
	Name        string `json:"name"`
	Path        string `json:"path"`
	Content     string `json:"content"`
	Sha         string `json:"sha"`
	URL         string `json:"url"`
	GitURL      string `json:"git_url"`
	HTMLURL     string `json:"html_url"`
	DownloadURL string `json:"download_url"`
	Links       struct {
		Git  string `json:"git"`
		Self string `json:"self"`
		HTML string `json:"html"`
	} `json:"_links"`
}

type OsFileSource struct {
	Type      string   `json:"type"`
	DeviceMap []string `json:"deviceMap"`
	Links     []struct {
		URL       string `json:"url"`
		Preferred bool   `json:"preferred"`
		Active    bool   `json:"active"`
	} `json:"links"`
	Hashes struct {
		Sha2256 string `json:"sha2-256"`
		Sha1    string `json:"sha1"`
	} `json:"hashes"`
	Size int64 `json:"size"`
}

// AppleDbOsFiles is an AppleDB osFiles object
type AppleDbOsFile struct {
	OS        string         `json:"osStr"`
	Version   string         `json:"version"`
	Build     string         `json:"build"`
	Released  string         `json:"released"`
	Beta      bool           `json:"beta"`
	DeviceMap []string       `json:"deviceMap"`
	Sources   []OsFileSource `json:"sources"`
}

type OsFiles []AppleDbOsFile

type ADBQuery struct {
	OS       string
	Version  string
	Build    string
	Device   string
	IsBeta   bool
	Proxy    string
	Insecure bool
	APIToken string
}

func (fs OsFiles) Query(query *ADBQuery) []OsFileSource {
	var sources []OsFileSource
	for _, f := range fs {
		if len(query.OS) > 0 && f.OS != query.OS {
			continue
		}
		if len(query.Version) > 0 && f.Version != query.Version {
			continue
		}
		if len(query.Build) > 0 && f.Build != query.Build {
			continue
		}
		if query.IsBeta && !f.Beta {
			continue
		}
		if len(query.Device) > 0 {
			for _, source := range f.Sources {
				if utils.StrSliceContains(source.DeviceMap, query.Device) {
					sources = append(sources, source)
				}
			}
		} else {
			sources = append(sources, f.Sources...)
		}
	}
	return sources
}

func AppleDBQuery(q *ADBQuery) ([]OsFileSource, error) {
	var osfiles OsFiles

	qurl, err := url.JoinPath("osFiles", q.OS)
	if err != nil {
		return nil, err
	}

	folders, err := queryGithubAPI(qurl, q.Proxy, q.APIToken, q.Insecure)
	if err != nil {
		return nil, err
	}

	for _, folder := range folders {
		build, version, found := strings.Cut(folder.Name, " - ")
		if !found {
			continue
		}
		if len(q.Version) > 0 && !strings.HasPrefix(q.Version, strings.TrimSuffix(version, "x")) {
			continue
		}
		if len(q.Build) > 0 && !strings.HasPrefix(q.Build, strings.TrimSuffix(build, "x")) {
			continue
		}

		qurl, err = url.JoinPath("osFiles", q.OS, folder.Name)
		if err != nil {
			return nil, err
		}
		files, err := queryGithubAPI(qurl, q.Proxy, q.APIToken, q.Insecure)
		if err != nil {
			return nil, err
		}

		for _, file := range files {
			of, err := getOsFiles(file.DownloadURL, q.Proxy, q.APIToken, q.Insecure)
			if err != nil {
				return nil, err
			}
			osfiles = append(osfiles, *of)
		}
	}

	return osfiles.Query(q), nil
}

func queryGithubAPI(path, proxy, api string, insecure bool) ([]GithubContentsResponse, error) {
	var contents []GithubContentsResponse

	req, err := http.NewRequest("GET", ApiContentsURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot create http GET request: %v", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Add("User-Agent", utils.RandomAgent())
	if len(api) > 0 {
		req.Header.Add("Authorization", "token "+api)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           GetProxy(proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("api returned status: %s", res.Status)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	res.Body.Close()

	if err := json.Unmarshal(body, &contents); err != nil {
		return nil, err
	}

	return contents, nil
}

func getOsFiles(path, proxy, api string, insecure bool) (*AppleDbOsFile, error) {
	var osfile AppleDbOsFile

	req, err := http.NewRequest("GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot create http GET request: %v", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Add("User-Agent", utils.RandomAgent())
	if len(api) > 0 {
		req.Header.Add("Authorization", "token "+api)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           GetProxy(proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("returned status: %s", res.Status)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	res.Body.Close()

	if err := json.Unmarshal(body, &osfile); err != nil {
		return nil, err
	}

	return &osfile, nil
}
