package download

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
)

const (
	preprocTagsURL = "https://raw.githubusercontent.com/blacktop/ipsw/apple_meta/github/tag_links.json"
	githubApiURL   = "https://api.github.com/orgs/apple-oss-distributions/repos?sort=updated&per_page=100"
	graphqlQuery   = `query ($endCursor: String) {
						organization(login: "apple-oss-distributions") {
							repositories(first: 100, after: $endCursor) {
								nodes {
									name
									refs(refPrefix: "refs/tags/", last: 1) {
										nodes {
											name
											target {
												__typename
												... on Tag {
													commitUrl
													target {
														... on Commit {
															zipballUrl
															tarballUrl
															author {
																name
																date
															}
														}
													}
												}
											}
										}
									}
								}
								pageInfo {
									hasNextPage
									endCursor
								}
							}
						}
					}`
)

type GithubRepos []githubRepo

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

type GithubReleaseAsset struct {
	ID            int       `json:"id,omitempty"`
	Name          string    `json:"name,omitempty"`
	URL           string    `json:"url,omitempty"`
	DownloadURL   string    `json:"browser_download_url,omitempty"`
	Size          int       `json:"size,omitempty"`
	DownloadCount int       `json:"download_count,omitempty"`
	CreatedAt     time.Time `json:"created_at,omitempty"`
	UpdatedAt     time.Time `json:"updated_at,omitempty"`
}

func (a GithubReleaseAsset) String() string {
	return a.Name
}

type GithubReleases []githubRelease

type githubRelease struct {
	ID          int                  `json:"id,omitempty"`
	URL         string               `json:"url,omitempty"`
	HtmlURL     string               `json:"html_url,omitempty"`
	TarballURL  string               `json:"tarball_url,omitempty"`
	Tag         string               `json:"tag_name,omitempty"`
	CreatedAt   time.Time            `json:"created_at,omitempty"`
	PublishedAt time.Time            `json:"published_at,omitempty"`
	Assets      []GithubReleaseAsset `json:"assets,omitempty"`
	Body        string               `json:"body,omitempty"`
}

type GithubTags []GithubTag

type GithubTag struct {
	Name   string       `json:"name,omitempty"`
	TarURL string       `json:"tarball_url,omitempty"`
	ZipURL string       `json:"zipball_url,omitempty"`
	Commit GithubCommit `json:"commit,omitempty"`
}

type GithubCommit struct {
	SHA  string    `json:"sha,omitempty"`
	URL  string    `json:"url,omitempty"`
	Date time.Time `json:"date,omitempty"`
}

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
			Proxy:           GetProxy(proxy),
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
			Proxy:           GetProxy(proxy),
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
			Proxy:           GetProxy(proxy),
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

// GetGithubIPSWReleases returns the list of releases for `ipsw`
func GetGithubIPSWReleases(proxy string, insecure bool, api string) (GithubReleases, error) {

	var releases GithubReleases

	req, err := http.NewRequest("GET", "https://api.github.com/repos/blacktop/ipsw/releases", nil)
	if err != nil {
		return nil, fmt.Errorf("cannot create http request: %v", err)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	if len(api) > 0 {
		req.Header.Add("Authorization", "token "+api)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           GetProxy(proxy),
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

// GetPreprocessedAppleOssTags returns a list of preprocessed apple oss tags
func GetPreprocessedAppleOssTags(proxy string, insecure bool) (map[string]GithubTag, error) {
	var tags map[string]GithubTag

	req, err := http.NewRequest("GET", preprocTagsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot create http request: %v", err)
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           GetProxy(proxy),
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

type Commit struct {
	OID        string `json:"oid"`
	ZipballUrl string `json:"zipballUrl"`
	TarballUrl string `json:"tarballUrl"`
	Author     struct {
		Name string    `json:"name,omitempty"`
		Date time.Time `json:"date,omitempty"`
	} `json:"author"`
}

type Repo struct {
	Name string
	Ref  struct {
		Nodes []struct {
			Name   string
			Target struct {
				Tag struct {
					CommitURL string `json:"commitUrl"`
					Target    struct {
						Commit `graphql:"... on Commit"`
					}
				} `graphql:"... on Tag"`
			}
		}
	} `graphql:"refs(refPrefix: \"refs/tags/\", last: 1)"`
}

// AppleOssGraphQLTags returns a list of apple-oss-distributions tags from the Github GraphQL API
func AppleOssGraphQLTags(proxy string, insecure bool, apikey string) (map[string]GithubTag, error) {
	tags := make(map[string]GithubTag)

	httpClient := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: apikey},
	))

	client := githubv4.NewClient(httpClient)

	var q struct {
		Organization struct {
			Repositories struct {
				Nodes    []Repo
				PageInfo struct {
					EndCursor   githubv4.String
					HasNextPage bool
				}
			} `graphql:"repositories(first: 100, after: $endCursor)"`
		} `graphql:"organization(login: \"apple-oss-distributions\")"`
	}

	variables := map[string]interface{}{
		"endCursor": (*githubv4.String)(nil), // Null after argument to get first page.
	}

	for {
		err := client.Query(context.Background(), &q, variables)
		if err != nil {
			return nil, err
		}
		for _, repo := range q.Organization.Repositories.Nodes {
			for _, ref := range repo.Ref.Nodes {
				tags[repo.Name] = GithubTag{
					Name:   repo.Name,
					TarURL: fmt.Sprintf("https://codeload.github.com/apple-oss-distributions/%s/tar.gz/refs/tags/%s", repo.Name, ref.Name),
					ZipURL: fmt.Sprintf("https://codeload.github.com/apple-oss-distributions/%s/zip/refs/tags/%s", repo.Name, ref.Name),
					Commit: GithubCommit{
						SHA:  ref.Target.Tag.Target.Commit.OID,
						URL:  ref.Target.Tag.CommitURL,
						Date: ref.Target.Tag.Target.Commit.Author.Date,
					},
				}
			}
		}
		if !q.Organization.Repositories.PageInfo.HasNextPage {
			break
		}
		variables["endCursor"] = githubv4.NewString(q.Organization.Repositories.PageInfo.EndCursor)
	}

	return tags, nil
}
