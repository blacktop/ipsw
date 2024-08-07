package download

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
)

const (
	// AppleDBRepoURL is the URL to the AppleDB github repo
	AppleDBRepoURL = "https://github.com/littlebyteorg/appledb"
	AppleDBGitURL  = "https://github.com/littlebyteorg/appledb.git"
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
	Type              string             `json:"type"`
	PrerequisiteBuild PrerequisiteBuilds `json:"prerequisiteBuild,omitempty"`
	DeviceMap         []string           `json:"deviceMap"`
	Links             []struct {
		URL    string `json:"url"`
		Active bool   `json:"active"`
	} `json:"links"`
	Hashes struct {
		Sha2256 string `json:"sha2-256"`
		Sha1    string `json:"sha1"`
	} `json:"hashes"`
	Size int64 `json:"size"`
}

type ReleasedDate time.Time

func (r *ReleasedDate) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), "\"")
	if s == "null" || s == "" {
		return nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return err
	}
	*r = ReleasedDate(t)
	return nil
}
func (r ReleasedDate) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(r))
}
func (r ReleasedDate) Format(s string) string {
	t := time.Time(r)
	return t.Format(s)
}

type PrerequisiteBuilds struct {
	Builds []string
}

func (p *PrerequisiteBuilds) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err == nil {
		p.Builds = []string{str}
		return nil
	}
	var slice []string
	if err := json.Unmarshal(b, &slice); err == nil {
		p.Builds = slice
		return nil
	}
	return fmt.Errorf("could not unmarshal PrerequisiteBuilds as string or []string")
}

// AppleDbOsFiles is an AppleDB osFiles object
type AppleDbOsFile struct {
	OS        string         `json:"osStr"`
	Version   string         `json:"version"`
	Build     string         `json:"build"`
	Released  ReleasedDate   `json:"released"`
	Beta      bool           `json:"beta"`
	RC        bool           `json:"rc"`
	Internal  bool           `json:"internal"`
	DeviceMap []string       `json:"deviceMap"`
	Sources   []OsFileSource `json:"sources"`
}

type OsFiles []AppleDbOsFile

func (fs OsFiles) Len() int {
	return len(fs)
}

func (fs OsFiles) Less(i, j int) bool {
	return time.Time(fs[i].Released).After(time.Time((fs[j].Released)))
}

func (fs OsFiles) Swap(i, j int) {
	fs[i], fs[j] = fs[j], fs[i]
}

func (fs OsFiles) Latest(query *ADBQuery) *AppleDbOsFile {
	var tmpFS OsFiles
	for _, f := range fs {
		if len(query.OSes) > 0 {
			for _, os := range query.OSes {
				if f.OS == os {
					continue
				}
			}
		}
		if query.IsBeta && !f.Beta {
			continue
		} else if query.IsRC && !f.RC {
			continue
		} else if query.IsRelease && (f.Beta || f.RC) {
			continue
		}
		if len(query.Version) > 0 && !strings.HasPrefix(f.Version, query.Version) {
			continue
		}
		tmpFS = append(tmpFS, f)
	}
	if len(tmpFS) == 0 {
		return nil
	}
	sort.Sort(tmpFS)
	return &tmpFS[0]
}

// Query returns a list of OsFileSource objects that match the query
func (fs OsFiles) Query(query *ADBQuery) []OsFileSource {
	var tmpFS OsFiles
	var sources []OsFileSource

	for _, f := range fs {
		if len(query.OSes) > 0 {
			for _, os := range query.OSes {
				if f.OS == os {
					continue
				}
			}
		}
		if query.IsBeta && !f.Beta {
			continue
		} else if query.IsRC && !f.RC {
			continue
		} else if query.IsRelease && (f.Beta || f.RC) {
			continue
		}
		if len(query.Version) > 0 && !strings.HasPrefix(f.Version, query.Version) {
			continue
		}
		if len(query.Build) > 0 && f.Build != query.Build {
			continue
		}
		tmpFS = append(tmpFS, f)
	}

	if query.Latest {
		var latestFS OsFiles
		sort.Sort(tmpFS)
		if len(tmpFS) > 0 {
			date := tmpFS[0].Released
			for _, f := range tmpFS {
				if f.Released == date {
					latestFS = append(latestFS, f)
				} else {
					break
				}
			}
		}
		tmpFS = latestFS
	}

	for _, f := range tmpFS {
		if len(query.Device) > 0 {
			for _, source := range f.Sources {
				if slices.Contains(source.DeviceMap, query.Device) {
					if len(query.Type) > 0 && source.Type == query.Type {
						sources = append(sources, source)
					}
				}
			}
		} else {
			for _, source := range f.Sources {
				if len(query.Type) > 0 && source.Type == query.Type {
					sources = append(sources, source)
				}
			}
		}
	}

	if query.Type == "ota" {
		if len(query.PrerequisiteBuild) > 0 {
			var tmpSources []OsFileSource
			for _, source := range sources {
				if slices.Contains(source.PrerequisiteBuild.Builds, query.PrerequisiteBuild) {
					tmpSources = append(tmpSources, source)
				}
			}
			sources = tmpSources
		} else {
			// if deltas are NOT requested, filter out sources that have prerequisite builds (only take full OTAs)
			if !query.Deltas {
				var tmpSources []OsFileSource
				for _, source := range sources {
					if len(source.PrerequisiteBuild.Builds) == 0 {
						tmpSources = append(tmpSources, source)
					}
				}
				sources = tmpSources
			}
		}
	}

	return sources
}

type ADBQuery struct {
	OSes              []string
	Type              string
	Version           string
	Build             string
	PrerequisiteBuild string
	Deltas            bool
	Device            string
	IsRelease         bool
	IsBeta            bool
	IsRC              bool
	Latest            bool
	Proxy             string
	Insecure          bool
	APIToken          string
	ConfigDir         string
}

func getLocalOsfiles(q *ADBQuery) (OsFiles, error) {
	var osfiles OsFiles

	if _, err := os.Stat(filepath.Join(q.ConfigDir, "appledb")); os.IsNotExist(err) {
		utils.Indent(log.Info, 2)(fmt.Sprintf("Git cloning local 'appledb' to %s", filepath.Join(q.ConfigDir, "appledb")))
		if _, err := utils.GitClone(AppleDBGitURL, filepath.Join(q.ConfigDir, "appledb")); err != nil {
			return nil, fmt.Errorf("failed to create local copy of 'appledb' repo: %v", err)
		}
	} else {
		utils.Indent(log.Info, 2)(fmt.Sprintf("Updating 'appledb' repo %s", filepath.Join(q.ConfigDir, "appledb")))
		if _, err := utils.GitRefresh(filepath.Join(q.ConfigDir, "appledb")); err != nil {
			return nil, fmt.Errorf("failed to update local copy of 'appledb' repo: %v", err)
		}
	}

	var folders []string
	if err := filepath.Walk(filepath.Join(q.ConfigDir, "appledb"), func(path string, f os.FileInfo, err error) error {
		if f.IsDir() {
			for _, os := range q.OSes {
				if strings.Contains(path, filepath.Join("osFiles", os)) {
					folders = append(folders, path)
				}
			}
		}
		return err
	}); err != nil {
		return nil, err
	}

	for _, folder := range folders {
		if !strings.Contains(folder, "Rapid Security Responses") {
			build, version, found := strings.Cut(filepath.Base(folder), " - ")
			if !found {
				continue
			}
			if len(q.Version) > 0 && !strings.HasPrefix(q.Version, strings.TrimSuffix(version, "x")) {
				continue
			}
			if len(q.Build) > 0 && !strings.HasPrefix(q.Build, strings.TrimSuffix(build, "x")) {
				continue
			}
		}
		if err := filepath.Walk(folder, func(path string, f os.FileInfo, err error) error {
			var osfile AppleDbOsFile
			if !f.IsDir() {
				dat, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				if err := json.Unmarshal(dat, &osfile); err != nil {
					log.Errorf("failed to unmarshal osfile for version %s (%s): %v", osfile.Version, osfile.Build, err)
					return nil
				}

				if strings.Contains(path, "Rapid Security Responses") {
					for i := range osfile.Sources {
						osfile.Sources[i].Type = "rsr"
					}
				}
				if osfile.Internal {
					return nil // skip internal metadata
				}

				osfiles = append(osfiles, osfile)
			}
			return err
		}); err != nil {
			return nil, err
		}
	}

	return osfiles, nil
}

func LocalAppleDBLatest(q *ADBQuery) (*AppleDbOsFile, error) {
	osfiles, err := getLocalOsfiles(q)
	if err != nil {
		return nil, err
	}
	return osfiles.Latest(q), nil
}

func LocalAppleDBQuery(q *ADBQuery) ([]OsFileSource, error) {
	osfiles, err := getLocalOsfiles(q)
	if err != nil {
		return nil, err
	}
	return osfiles.Query(q), nil
}

func AppleDBQuery(q *ADBQuery) ([]OsFileSource, error) {
	var osfiles OsFiles

	for _, os := range q.OSes {
		qurl, err := url.JoinPath("osFiles", os)
		if err != nil {
			return nil, err
		}

		folders, err := queryGithubAPI(qurl, q.Proxy, q.APIToken, q.Insecure)
		if err != nil {
			return nil, err
		}

		for _, folder := range folders {
			if strings.Contains(folder.Path, "Rapid Security Responses") {
				for _, file := range folders {
					of, err := getOsFiles(file.Path, q.Proxy, q.APIToken, q.Insecure)
					if err != nil {
						log.WithError(err).Errorf("failed to download %s", path.Base(file.DownloadURL))
						continue
					}
					if strings.Contains(file.Path, "Rapid Security Responses") {
						for i := range of.Sources {
							of.Sources[i].Type = "rsr"
						}
					}
					osfiles = append(osfiles, *of)
				}

				return osfiles.Query(q), nil
			}

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

			qurl, err = url.JoinPath("osFiles", os, folder.Name)
			if err != nil {
				return nil, err
			}

			files, err := queryGithubAPI(qurl, q.Proxy, q.APIToken, q.Insecure)
			if err != nil {
				return nil, err
			}

			for _, file := range files {
				of, err := getOsFiles(file.Path, q.Proxy, q.APIToken, q.Insecure)
				if err != nil {
					log.WithError(err).Errorf("failed to download %s", path.Base(file.DownloadURL))
					continue
				}
				if strings.Contains(file.Path, "Rapid Security Responses") {
					for i := range of.Sources {
						of.Sources[i].Type = "rsr"
					}
				}
				osfiles = append(osfiles, *of)
			}
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
		return nil, fmt.Errorf("failed to unmarshal []GithubContentsResponse JSON: %w", err)
	}

	return contents, nil
}

func getOsFiles(path, proxy, api string, insecure bool) (*AppleDbOsFile, error) {
	var osfile AppleDbOsFile

	req, err := http.NewRequest("GET", ApiContentsURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot create http GET request: %v", err)
	}
	req.Header.Set("Accept", "application/vnd.github.raw")
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
		return nil, fmt.Errorf("returned status: %s", res.Status)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	res.Body.Close()

	if err := json.Unmarshal(body, &osfile); err != nil {
		return nil, fmt.Errorf("failed to unmarshal AppleDbOsFile JSON: %w", err)
	}

	return &osfile, nil
}
