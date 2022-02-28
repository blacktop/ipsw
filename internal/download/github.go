package download

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	preprocTagsURL = "https://raw.githubusercontent.com/blacktop/ipsw/apple_meta/github/tag_links.json"
	githubApiURL   = "https://api.github.com/orgs/apple-oss-distributions/repos?sort=updated&per_page=100"
	graphqlQuery   = `query ($endCursor: String) {
					rateLimit {
						cost
						remaining
						resetAt
					}
					search(
						query: "org:apple-oss-distributions, archived:false"
						type: REPOSITORY
						first: 100
						after: $endCursor
					) {
						repositoryCount
						pageInfo {
							endCursor
							hasNextPage
						}
						edges {
							node {
								... on Repository {
									name
									refs(
										first: 1
										refPrefix: "refs/tags/"
										orderBy: { field: TAG_COMMIT_DATE, direction: DESC }
									) {
										nodes {
											name
											target {
												__typename
												... on Tag {
													oid
													name
													commitUrl
													target {
														oid
													}
												}
												... on Commit {
													commit_message: message
												}
											}
										}
									}
								}
							}
						}
					}
				}`
)

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

type GithubReleases []githubRelease

type GithubCommit struct {
	SHA string `json:"sha,omitempty"`
	URL string `json:"url,omitempty"`
}

type GithubTag struct {
	Name   string       `json:"name,omitempty"`
	TarURL string       `json:"tarball_url,omitempty"`
	ZipURL string       `json:"zipball_url,omitempty"`
	Commit GithubCommit `json:"commit,omitempty"`
}

type GithubTags []GithubTag

type githubTar struct {
	Name   string `json:"name,omitempty"`
	Tag    string `json:"tag,omitempty"`
	TarURL string `json:"tar_url,omitempty"`
	ZipURL string `json:"zip_url,omitempty"`
}

type graphqlRateLimit struct {
	Cost      int       `json:"cost,omitempty"`
	Remaining int       `json:"remaining,omitempty"`
	ResetAt   time.Time `json:"resetAt,omitempty"`
}
type graphqlNode struct {
	Name   string `json:"name,omitempty"`
	Target struct {
		Type      string `json:"__typename,omitempty"`
		OID       string `json:"oid,omitempty"`
		Name      string `json:"name,omitempty"`
		CommitURL string `json:"commitUrl,omitempty"`
		Target    struct {
			OID string `json:"oid,omitempty"`
		} `json:"target,omitempty"`
	} `json:"target,omitempty"`
}
type graphqlEdge struct {
	Node struct {
		Name string `json:"name,omitempty"`
		Refs struct {
			Nodes []graphqlNode `json:"nodes,omitempty"`
		} `json:"refs,omitempty"`
	} `json:"node,omitempty"`
}
type graphqlSearch struct {
	RepositoryCount int `json:"repositoryCount,omitempty"`
	PageInfo        struct {
		EndCursor string `json:"endCursor,omitempty"`
		HasNext   bool   `json:"hasNextPage,omitempty"`
	} `json:"pageInfo,omitempty"`
	Edges []graphqlEdge `json:"edges,omitempty"`
}
type GithubGraphQLData struct {
	Data struct {
		RateLimit graphqlRateLimit `json:"rateLimit,omitempty"`
		Search    graphqlSearch    `json:"search,omitempty"`
	} `json:"data,omitempty"`
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

type graphQLRequest struct {
	Query     string `json:"query,omitempty"`
	Variables struct {
		EndCursor string `json:"endCursor,omitempty"`
	} `json:"variables,omitempty"`
}

// AppleOssGraphQLTags returns a list of apple-oss-distributions tags from the Github GraphQL API
func AppleOssGraphQLTags(proxy string, insecure bool, api, cursor string) (*GithubGraphQLData, error) {
	var data GithubGraphQLData

	qlRequest := graphQLRequest{
		Query: graphqlQuery,
	}

	if len(cursor) > 0 {
		qlRequest.Variables.EndCursor = cursor

	}
	jsonValue, err := json.Marshal(qlRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal graphQL query json data: %v", err)
	}

	req, err := http.NewRequest("POST", "https://api.github.com/graphql", bytes.NewBuffer(jsonValue))
	if err != nil {
		return nil, fmt.Errorf("cannot create http request: %v", err)
	}
	req.Header.Set("Accept", "application/json")
	if len(api) > 0 {
		req.Header.Add("Authorization", "Bearer "+api)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           GetProxy(proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
		Timeout: time.Second * 10,
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

	ioutil.WriteFile("/tmp/graphql.json", document, 0644)

	if err := json.Unmarshal(document, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal the github api JSON: %v", err)
	}

	return &data, nil
}
