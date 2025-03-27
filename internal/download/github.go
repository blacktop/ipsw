package download

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
)

const (
	preprocTagsURL       = "https://raw.githubusercontent.com/blacktop/ipsw/apple_meta/github/tag_links.json"
	preprocWebKitTagsURL = "https://raw.githubusercontent.com/blacktop/ipsw/apple_meta/github/webkit_tags.json"
	githubApiURL         = "https://api.github.com/orgs/apple-oss-distributions/repos?sort=updated&per_page=100"
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
	PublishedAt time.Time `json:"published_at"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
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
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
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
	CreatedAt   time.Time            `json:"created_at"`
	PublishedAt time.Time            `json:"published_at"`
	Assets      []GithubReleaseAsset `json:"assets,omitempty"`
	Body        string               `json:"body,omitempty"`
}

type GithubTags []GithubTag

type GithubTag struct {
	Name   string       `json:"name,omitempty"`
	TarURL string       `json:"tarball_url,omitempty"`
	ZipURL string       `json:"zipball_url,omitempty"`
	Commit GithubCommit `json:"commit"`
}

type GithubCommit struct {
	SHA  string    `json:"sha,omitempty"`
	URL  string    `json:"url,omitempty"`
	Date time.Time `json:"date"`
}

func GetLatestTag(prod, proxy string, insecure bool, api string) (string, error) {
	var tags []GithubTag
	req, err := http.NewRequest("GET", "https://api.github.com/repos/apple-oss-distributions/"+prod+"/tags", nil)
	if err != nil {
		return "", fmt.Errorf("cannot create http request: %v", err)
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
		return "", fmt.Errorf("client failed to perform request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("failed to connect to URL: %s", resp.Status)
	}

	document, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read github api JSON: %v", err)
	}

	if err := json.Unmarshal(document, &tags); err != nil {
		return "", fmt.Errorf("failed to unmarshal the github api JSON: %v", err)
	}

	return tags[0].Name, nil
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

	document, err := io.ReadAll(resp.Body)
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

	document, err := io.ReadAll(resp.Body)
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

		document, err := io.ReadAll(resp.Body)
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
		for link := range strings.SplitSeq(links[0], ",") {
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

	document, err := io.ReadAll(resp.Body)
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

	document, err := io.ReadAll(resp.Body)
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

	document, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read github api JSON: %v", err)
	}

	if err := json.Unmarshal(document, &tags); err != nil {
		return nil, fmt.Errorf("failed to unmarshal the github api JSON: %v", err)
	}

	return tags, nil
}

func GetPreprocessedWebKitTags(proxy string, insecure bool) ([]GithubTag, error) {
	var tags []GithubTag

	req, err := http.NewRequest("GET", preprocWebKitTagsURL, nil)
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

	document, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read github api JSON: %v", err)
	}

	if err := json.Unmarshal(document, &tags); err != nil {
		return nil, fmt.Errorf("failed to unmarshal the github api JSON: %v", err)
	}

	return tags, nil
}

// Commit represents a GitHub GraphQL Commit
type Commit struct {
	OID          githubv4.GitObjectID `json:"oid"`
	URL          githubv4.URI         `graphql:"commitUrl" json:"url"`
	ChangedFiles githubv4.Int         `graphql:"changedFilesIfAvailable" json:"changed_files"`
	Additions    githubv4.Int         `json:"additions"`
	Deletions    githubv4.Int         `json:"deletions"`
	MsgHeadline  githubv4.String      `graphql:"messageHeadline" json:"message_headline"`
	Message      githubv4.String      `graphql:"message" json:"-"`
	MsgBody      githubv4.String      `graphql:"messageBody" json:"message_body"`
	Author       struct {
		Name  githubv4.String       `json:"name,omitempty"`
		Email githubv4.String       `json:"email,omitempty"`
		Date  githubv4.GitTimestamp `json:"date"`
	} `json:"author"`
	ZipballURL string `json:"zipballUrl"`
	TarballURL string `json:"tarballUrl"`
}

// GetGithubCommits returns a list of commits for a given pattern
func GetGithubCommits(org, repo, branch, file, pattern string, days int, proxy string, insecure bool, apikey string) ([]Commit, error) {
	var commits []Commit

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regexp '%s': %v", pattern, err)
	}

	httpClient := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: apikey},
	))

	// httpClient.Transport = &http.Transport{
	// 	Proxy:           GetProxy(proxy),
	// 	TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	// }

	client := githubv4.NewClient(httpClient)

	var q struct {
		Repository struct {
			Ref struct {
				Target struct {
					Commit struct {
						History struct {
							Nodes []struct {
								Commit
							}
							PageInfo struct {
								EndCursor   githubv4.String
								HasNextPage bool
							}
						} `graphql:"history(path: $filePath, since: $sinceDate, after: $endCursor)"`
					} `graphql:"... on Commit"`
				}
			} `graphql:"ref(qualifiedName: $repoRef)"`
		} `graphql:"repository(owner: $repoOrg, name: $repoName)"`
	}

	var filePath any
	filePath = (*githubv4.String)(nil)
	if file != "" {
		filePath = githubv4.String(file)
	}

	variables := map[string]any{
		"repoOrg":   githubv4.String(org),
		"repoName":  githubv4.String(repo),
		"repoRef":   githubv4.String(branch), // "main" etc
		"filePath":  filePath,
		"sinceDate": githubv4.GitTimestamp{Time: time.Now().AddDate(0, 0, -days)},
		"endCursor": (*githubv4.String)(nil), // Null after argument to get first page.
	}

	for {
		if err := client.Query(context.Background(), &q, variables); err != nil {
			return nil, err
		}

		for _, commit := range q.Repository.Ref.Target.Commit.History.Nodes {
			if re.MatchString(string(commit.Message)) {
				commits = append(commits, commit.Commit)
			}
		}

		if !q.Repository.Ref.Target.Commit.History.PageInfo.HasNextPage {
			break
		}

		variables["endCursor"] = githubv4.NewString(q.Repository.Ref.Target.Commit.History.PageInfo.EndCursor)
	}

	return commits, nil
}

type Repo struct {
	Name string
}

func GetLatestTagsV2(owner, repo string, limit int, proxy string, insecure bool, apikey string) ([]string, error) {
	httpClient := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: apikey},
	))

	client := githubv4.NewClient(httpClient)

	var q struct {
		Repository struct {
			Refs struct {
				Edges []struct {
					Node struct {
						Name string
					}
				}
			} `graphql:"refs(refPrefix: \"refs/tags/\", first: $limit, orderBy: { field: TAG_COMMIT_DATE, direction: DESC })"`
		} `graphql:"repository(owner: $owner, name: $name)"`
		RateLimit struct {
			Cost      githubv4.Int
			Limit     githubv4.Int
			Remaining githubv4.Int
			ResetAt   githubv4.DateTime
		}
	}

	if limit == 0 {
		limit = 1
	}

	variables := map[string]any{
		"owner": githubv4.String(owner),
		"name":  githubv4.String(repo),
		"limit": githubv4.Int(limit),
	}

	for {
		if err := client.Query(context.Background(), &q, variables); err != nil {
			if strings.Contains(err.Error(), "API rate limit exceeded") ||
				strings.Contains(err.Error(), "was submitted too quickly") {
				// Handle rate limit error
				var rateLimitQuery struct {
					RateLimit struct {
						Cost      githubv4.Int
						Limit     githubv4.Int
						Remaining githubv4.Int
						ResetAt   githubv4.DateTime
					}
				}
				if err := client.Query(context.Background(), &rateLimitQuery, nil); err != nil {
					return nil, fmt.Errorf("failed to query GraphQL API for rate limit: %w", err)
				}
				resetTime := rateLimitQuery.RateLimit.ResetAt.Time
				log.Warnf("rate limit exceeded, waiting for %s", time.Until(resetTime))
				time.Sleep(time.Until(resetTime) + 1*time.Second)
				continue
			}
			return nil, err
		}
		break
	}

	if len(q.Repository.Refs.Edges) > 0 {
		var tags []string
		for _, edge := range q.Repository.Refs.Edges {
			tags = append(tags, edge.Node.Name)
		}
		return tags, nil
	}

	return nil, fmt.Errorf("no tags found for repository %s", repo)
}

// AppleOssGraphQLTags returns a list of apple-oss-distributions tags from the Github GraphQL API
func AppleOssGraphQLTags(repo string, limit int, proxy string, insecure bool, apikey string) (map[string][]GithubTag, error) {
	tags := make(map[string][]GithubTag)

	httpClient := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: apikey},
	))

	client := githubv4.NewClient(httpClient)

	var repos []string
	if len(repo) > 0 {
		repos = append(repos, repo)
	} else { // GET ALL THE REPO NAMES
		var repoQuery struct {
			Organization struct {
				Repositories struct {
					Nodes    []Repo
					PageInfo struct {
						EndCursor   githubv4.String
						HasNextPage bool
					}
				} `graphql:"repositories(first: 100, after: $endCursor)"`
			} `graphql:"organization(login: $login)"`
		}
		variables := map[string]any{
			"login":     githubv4.String("apple-oss-distributions"),
			"endCursor": (*githubv4.String)(nil), // Null after argument to get first page.
		}
		for {
			err := client.Query(context.Background(), &repoQuery, variables)
			if err != nil {
				return nil, err
			}
			for _, repo := range repoQuery.Organization.Repositories.Nodes {
				repos = append(repos, repo.Name)
			}
			if !repoQuery.Organization.Repositories.PageInfo.HasNextPage {
				break
			}
			variables["endCursor"] = githubv4.String(repoQuery.Organization.Repositories.PageInfo.EndCursor)
		}
	}

	var tagQuery struct {
		Repository struct {
			Refs struct {
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
				PageInfo struct {
					EndCursor   githubv4.String
					HasNextPage bool
				}
			} `graphql:"refs(refPrefix: \"refs/tags/\", first: $limit, after: $endCursor, orderBy: { field: TAG_COMMIT_DATE, direction: DESC})"`
		} `graphql:"repository(owner: $owner, name: $name)"`
	}

	for _, repo := range repos {
	loop:
		for {
			variables := map[string]any{
				"owner":     githubv4.String("apple-oss-distributions"),
				"name":      githubv4.String(repo),
				"limit":     githubv4.Int(limit),
				"endCursor": (*githubv4.String)(nil), // Null after argument to get first page.
			}
			err := client.Query(context.Background(), &tagQuery, variables)
			if err != nil {
				if strings.Contains(err.Error(), "API rate limit exceeded") ||
					strings.Contains(err.Error(), "was submitted too quickly") {
					// rate limit
					var rateLimitQuery struct {
						RateLimit struct {
							ResetAt githubv4.DateTime
						}
					}
					if err := client.Query(context.Background(), &rateLimitQuery, variables); err != nil {
						return nil, fmt.Errorf("failed to query GraphQL API for rate limit: %w", err)
					}
					resetTime := rateLimitQuery.RateLimit.ResetAt.Time
					log.Warnf("rate limit exceeded, waiting for %s", time.Until(resetTime))
					time.Sleep(time.Until(resetTime) + 1*time.Second)
					goto loop
				} else {
					return nil, fmt.Errorf("failed to query GraphQL API for %s tags: %w", repo, err)
				}
			}
			for _, ref := range tagQuery.Repository.Refs.Nodes {
				tags[repo] = append(tags[repo], GithubTag{
					Name:   ref.Name,
					TarURL: fmt.Sprintf("https://github.com/apple-oss-distributions/%s/archive/refs/tags/%s.tar.gz", repo, ref.Name),
					ZipURL: fmt.Sprintf("https://github.com/apple-oss-distributions/%s/archive/refs/tags/%s.zip", repo, ref.Name),
					Commit: GithubCommit{
						SHA:  string(ref.Target.Tag.Target.Commit.OID),
						URL:  ref.Target.Tag.CommitURL,
						Date: ref.Target.Tag.Target.Commit.Author.Date.Time,
					},
				})
				if len(tags[repo]) == limit {
					break loop
				}
			}
			if !tagQuery.Repository.Refs.PageInfo.HasNextPage {
				break
			}
			variables["endCursor"] = githubv4.String(tagQuery.Repository.Refs.PageInfo.EndCursor)
		}
	}

	return tags, nil
}

func WebKitGraphQLTags(proxy string, insecure bool, apikey string) ([]GithubTag, error) {
	var tags []GithubTag

	httpClient := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: apikey},
	))

	client := githubv4.NewClient(httpClient)

	var q struct {
		Repository struct {
			Refs struct {
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
				PageInfo struct {
					EndCursor   githubv4.String
					HasNextPage bool
				}
			} `graphql:"refs(refPrefix: \"refs/tags/\", first: 100, after: $endCursor, orderBy: { field: TAG_COMMIT_DATE, direction: DESC})"`
		} `graphql:"repository(owner: \"WebKit\", name: \"WebKit\")"`
	}

	variables := map[string]any{
		"endCursor": (*githubv4.String)(nil), // Null after argument to get first page.
	}

	for {
		err := client.Query(context.Background(), &q, variables)
		if err != nil {
			return nil, err
		}
		for _, ref := range q.Repository.Refs.Nodes {
			tags = append(tags, GithubTag{
				Name:   ref.Name,
				TarURL: fmt.Sprintf("https://github.com/WebKit/WebKit/archive/refs/tags/%s.tar.gz", ref.Name),
				ZipURL: fmt.Sprintf("https://github.com/WebKit/WebKit/archive/refs/tags/%s.zip", ref.Name),
				Commit: GithubCommit{
					SHA:  string(ref.Target.Tag.Target.Commit.OID),
					URL:  ref.Target.Tag.CommitURL,
					Date: ref.Target.Tag.Target.Commit.Author.Date.Time,
				},
			})
		}
		if !q.Repository.Refs.PageInfo.HasNextPage {
			break
		}
		variables["endCursor"] = githubv4.NewString(q.Repository.Refs.PageInfo.EndCursor)
	}

	return tags, nil
}
