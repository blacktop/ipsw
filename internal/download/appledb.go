package download

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	PrerequisiteBuild PrerequisiteBuilds `json:"prerequisiteBuild"`
	DeviceMap         []string           `json:"deviceMap"`
	Links             []AppleDBLink      `json:"links"`
	Hashes            AppleDBHashes      `json:"hashes"`
	Size              int64              `json:"size"`
	sizeKnown         bool
}

type AppleDBLink struct {
	URL    string `json:"url"`
	Active bool   `json:"active"`
}

type AppleDBHashes struct {
	SHA256      string `json:"sha2-256"`
	SHA1        string `json:"sha1"`
	sha256Known bool
	sha1Known   bool
}

func (h *AppleDBHashes) UnmarshalJSON(data []byte) error {
	*h = AppleDBHashes{}
	var decoded struct {
		SHA256 *string `json:"sha2-256"`
		SHA1   *string `json:"sha1"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	if decoded.SHA256 != nil {
		h.SHA256 = *decoded.SHA256
		h.sha256Known = true
	}
	if decoded.SHA1 != nil {
		h.SHA1 = *decoded.SHA1
		h.sha1Known = true
	}
	return nil
}

func (s *OsFileSource) UnmarshalJSON(data []byte) error {
	*s = OsFileSource{}
	var decoded struct {
		Type              string             `json:"type"`
		PrerequisiteBuild PrerequisiteBuilds `json:"prerequisiteBuild"`
		DeviceMap         []string           `json:"deviceMap"`
		Links             []AppleDBLink      `json:"links"`
		Hashes            AppleDBHashes      `json:"hashes"`
		Size              *int64             `json:"size"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	s.Type = decoded.Type
	s.PrerequisiteBuild = decoded.PrerequisiteBuild
	s.DeviceMap = decoded.DeviceMap
	s.Links = decoded.Links
	s.Hashes = decoded.Hashes
	if decoded.Size != nil {
		s.Size = *decoded.Size
		s.sizeKnown = true
	}
	return nil
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
	OS                     string         `json:"osStr"`
	Version                string         `json:"version"`
	Build                  string         `json:"build"`
	Released               ReleasedDate   `json:"released"`
	Beta                   bool           `json:"beta"`
	RC                     bool           `json:"rc"`
	Internal               bool           `json:"internal"`
	HideFromLatestVersions bool           `json:"hideFromLatestVersions"`
	DeviceMap              []string       `json:"deviceMap"`
	Sources                []OsFileSource `json:"sources"`
	canonicalOS            string
}

// AppleDBRecord retains the release identity associated with one source that
// matched an ADBQuery. Query consumers use this as the authoritative result so
// a source never has to recover its version or build from a download URL.
type AppleDBRecord struct {
	OS          string
	Version     string
	Build       string
	Released    ReleasedDate
	ReleaseDate *string
	Channel     string
	ActiveURL   *string
	SHA256      *string
	SHA1        *string
	Size        *int64
	OsFileSource
}

type OsFiles []AppleDbOsFile

func (fs OsFiles) Len() int {
	return len(fs)
}

func (fs OsFiles) Less(i, j int) bool {
	return appleDBReleaseLess(fs[i], fs[j])
}

func (fs OsFiles) Swap(i, j int) {
	fs[i], fs[j] = fs[j], fs[i]
}

// hasDownloadableSource reports whether f carries at least one source that
// Query would emit for this query — the same Type/Device match plus the OTA
// prerequisite/delta filtering Query applies afterward. Latest relies on it so
// --show-latest only reports a build the download step can actually fetch: an
// RC that ships OTA-only is skipped under --type ipsw, and a build whose only
// OTA sources are deltas is skipped under a full-OTA query. Otherwise detect
// picks a build the download then fails on ("no results found").
func (f AppleDbOsFile) hasDownloadableSource(query *ADBQuery) bool {
	if len(query.Type) == 0 && len(query.Device) == 0 {
		return true // no source constraint to enforce
	}
	for _, source := range f.Sources {
		if len(query.Type) > 0 && source.Type != query.Type {
			continue
		}
		if len(query.Device) > 0 && !slices.Contains(source.DeviceMap, query.Device) {
			continue
		}
		// Mirror Query's OTA-specific source filtering: a prerequisite-build
		// query keeps only delta sources for that prereq; a default (non-delta)
		// query keeps only full OTAs (no prerequisite builds).
		if query.Type == "ota" {
			if len(query.PrerequisiteBuild) > 0 {
				if !slices.Contains(source.PrerequisiteBuild.Builds, query.PrerequisiteBuild) {
					continue
				}
			} else if !query.Deltas && len(source.PrerequisiteBuild.Builds) > 0 {
				continue
			}
		}
		return true
	}
	return false
}

func (fs OsFiles) Latest(query *ADBQuery) *AppleDbOsFile {
	var tmpFS OsFiles
	for _, f := range fs {
		if len(query.OSes) > 0 && !slices.Contains(query.OSes, appleDBOSFamily(f)) {
			continue
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
		if query.Latest && f.HideFromLatestVersions {
			continue
		}
		if !f.hasDownloadableSource(query) {
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

// Query returns release/source records that match the query.
func (fs OsFiles) Query(query *ADBQuery) []AppleDBRecord {
	var tmpFS OsFiles
	var records []AppleDBRecord

	for _, f := range fs {
		if len(query.OSes) > 0 && !slices.Contains(query.OSes, appleDBOSFamily(f)) {
			continue
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
		if query.Latest && f.HideFromLatestVersions {
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
		for _, source := range f.Sources {
			if !sourceMatchesQuery(source, query) {
				continue
			}
			records = append(records, AppleDBRecord{
				OS:           appleDBOSFamily(f),
				Version:      f.Version,
				Build:        f.Build,
				Released:     f.Released,
				ReleaseDate:  appleDBReleaseDate(f.Released),
				Channel:      appleDBChannel(f),
				ActiveURL:    activeAppleDBURL(source),
				SHA256:       source.Hashes.sha256Value(),
				SHA1:         source.Hashes.sha1Value(),
				Size:         source.sizeValue(),
				OsFileSource: canonicalAppleDBSource(source),
			})
		}
	}

	SortAppleDBRecords(records)
	return records
}

func sourceMatchesQuery(source OsFileSource, query *ADBQuery) bool {
	if len(query.Type) == 0 || source.Type != query.Type {
		return false
	}
	if len(query.Device) > 0 && !slices.Contains(source.DeviceMap, query.Device) {
		return false
	}
	if query.Type == "rsr" {
		return len(query.PrerequisiteBuild) == 0 || slices.Contains(source.PrerequisiteBuild.Builds, query.PrerequisiteBuild)
	}
	if query.Type != "ota" {
		return true
	}
	if len(query.PrerequisiteBuild) > 0 {
		return slices.Contains(source.PrerequisiteBuild.Builds, query.PrerequisiteBuild)
	}
	return query.Deltas || len(source.PrerequisiteBuild.Builds) == 0
}

func appleDBChannel(f AppleDbOsFile) string {
	if f.RC {
		return OTAChannelRC
	}
	if f.Beta {
		return OTAChannelBeta
	}
	return OTAChannelRelease
}

func canonicalAppleDBSource(source OsFileSource) OsFileSource {
	source.PrerequisiteBuild.Builds = slices.Clone(source.PrerequisiteBuild.Builds)
	sort.Strings(source.PrerequisiteBuild.Builds)
	source.DeviceMap = slices.Clone(source.DeviceMap)
	sort.Strings(source.DeviceMap)
	source.Links = slices.Clone(source.Links)
	return source
}

func appleDBOSFamily(f AppleDbOsFile) string {
	if f.canonicalOS != "" {
		return f.canonicalOS
	}
	return f.OS
}

func appleDBReleaseDate(released ReleasedDate) *string {
	if time.Time(released).IsZero() {
		return nil
	}
	value := released.Format("2006-01-02")
	return &value
}

func activeAppleDBURL(source OsFileSource) *string {
	for _, link := range source.Links {
		if link.Active && link.URL != "" {
			value := link.URL
			return &value
		}
	}
	return nil
}

func (h AppleDBHashes) sha256Value() *string {
	if !h.sha256Known && h.SHA256 == "" {
		return nil
	}
	value := h.SHA256
	return &value
}

func (h AppleDBHashes) sha1Value() *string {
	if !h.sha1Known && h.SHA1 == "" {
		return nil
	}
	value := h.SHA1
	return &value
}

func (s OsFileSource) sizeValue() *int64 {
	if !s.sizeKnown && s.Size == 0 {
		return nil
	}
	value := s.Size
	return &value
}

func appleDBReleaseLess(a, b AppleDbOsFile) bool {
	aReleased := time.Time(a.Released)
	bReleased := time.Time(b.Released)
	if !aReleased.Equal(bReleased) {
		return aReleased.After(bReleased)
	}
	if cmp := utils.Compare(a.Version, b.Version); cmp != 0 {
		return cmp > 0
	}
	if a.Version != b.Version {
		return a.Version > b.Version
	}
	if appleDBOSFamily(a) != appleDBOSFamily(b) {
		return appleDBOSFamily(a) < appleDBOSFamily(b)
	}
	return a.Build > b.Build
}

// SortAppleDBRecords puts matched records into the schema's deterministic
// release/artifact order. Callers may safely sort a cloned slice defensively.
func SortAppleDBRecords(records []AppleDBRecord) {
	sort.Slice(records, func(i, j int) bool {
		return appleDBRecordLess(records[i], records[j])
	})
}

func appleDBRecordLess(a, b AppleDBRecord) bool {
	aReleased := time.Time(a.Released)
	bReleased := time.Time(b.Released)
	if !aReleased.Equal(bReleased) {
		return aReleased.After(bReleased)
	}
	if cmp := utils.Compare(a.Version, b.Version); cmp != 0 {
		return cmp > 0
	}
	if a.Version != b.Version {
		return a.Version > b.Version
	}
	if a.OS != b.OS {
		return a.OS < b.OS
	}
	if a.Build != b.Build {
		return a.Build > b.Build
	}
	if a.Channel != b.Channel {
		return a.Channel < b.Channel
	}
	if cmp := appleDBSourceCompare(a.OsFileSource, b.OsFileSource); cmp != 0 {
		return cmp < 0
	}
	if cmp := compareOptionalString(a.ActiveURL, b.ActiveURL); cmp != 0 {
		return cmp < 0
	}
	if cmp := compareOptionalString(a.SHA256, b.SHA256); cmp != 0 {
		return cmp < 0
	}
	if cmp := compareOptionalString(a.SHA1, b.SHA1); cmp != 0 {
		return cmp < 0
	}
	return compareOptionalInt64(a.Size, b.Size) < 0
}

func appleDBSourceCompare(a, b OsFileSource) int {
	if a.Type != b.Type {
		return strings.Compare(a.Type, b.Type)
	}
	if cmp := slices.Compare(a.PrerequisiteBuild.Builds, b.PrerequisiteBuild.Builds); cmp != 0 {
		return cmp
	}
	if cmp := slices.Compare(a.DeviceMap, b.DeviceMap); cmp != 0 {
		return cmp
	}
	return 0
}

func compareOptionalString(a, b *string) int {
	if a == nil && b == nil {
		return 0
	}
	if a == nil {
		return 1
	}
	if b == nil {
		return -1
	}
	return strings.Compare(*a, *b)
}

func compareOptionalInt64(a, b *int64) int {
	if a == nil && b == nil {
		return 0
	}
	if a == nil {
		return 1
	}
	if b == nil {
		return -1
	}
	if *a < *b {
		return -1
	}
	if *a > *b {
		return 1
	}
	return 0
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
	NoUpdate          bool
}

// ensureLocalAppleDB returns the path of the local AppleDB checkout under
// configDir, cloning or refreshing it as needed. With noUpdate it runs no Git:
// a missing or empty checkout is an error, never stale or empty results.
func ensureLocalAppleDB(configDir string, noUpdate bool) (string, error) {
	repo := filepath.Join(configDir, "appledb")
	if noUpdate {
		if !fileExists(filepath.Join(repo, "osFiles")) {
			return "", fmt.Errorf("no usable local AppleDB checkout at %s: rerun without --no-update to clone it", repo)
		}
		utils.Indent(log.Debug, 2)(fmt.Sprintf("Skipping update of 'appledb' repo %s (--no-update)", repo))
		return repo, nil
	}
	if _, err := os.Stat(repo); os.IsNotExist(err) {
		utils.Indent(log.Info, 2)(fmt.Sprintf("Git cloning local 'appledb' to %s", repo))
		if _, err := utils.GitClone(AppleDBGitURL, repo); err != nil {
			return "", fmt.Errorf("failed to create local copy of 'appledb' repo: %v", err)
		}
		return repo, nil
	}
	utils.Indent(log.Debug, 2)(fmt.Sprintf("Updating 'appledb' repo %s", repo))
	if _, err := utils.GitRefresh(repo); err != nil {
		return "", fmt.Errorf("failed to update local copy of 'appledb' repo: %v", err)
	}
	return repo, nil
}

func getLocalOsfiles(q *ADBQuery) (OsFiles, error) {
	var osfiles OsFiles

	repo, err := ensureLocalAppleDB(q.ConfigDir, q.NoUpdate)
	if err != nil {
		return nil, err
	}

	for _, osFamily := range q.OSes {
		root := localAppleDBOSRoot(repo, osFamily, q.Type)
		if err := walkLocalAppleDB(root, func(filePath string, info os.FileInfo) error {
			if info.IsDir() || filepath.Ext(filePath) != ".json" {
				return nil
			}
			if !appleDBReleaseFolderMatches(filepath.Base(filepath.Dir(filePath)), q) {
				return nil
			}
			dat, err := os.ReadFile(filePath)
			if err != nil {
				return err
			}
			var osfile AppleDbOsFile
			if err := json.Unmarshal(dat, &osfile); err != nil {
				log.Errorf("failed to unmarshal osfile for version %s (%s): %v", osfile.Version, osfile.Build, err)
				return nil
			}
			if prepareAppleDBOSFile(&osfile, osFamily, q.Type) {
				osfiles = append(osfiles, osfile)
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	return osfiles, nil
}

func walkLocalAppleDB(root string, visit func(string, os.FileInfo) error) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return visit(path, info)
	})
}

func LocalAppleDBLatest(q *ADBQuery) (*AppleDbOsFile, error) {
	osfiles, err := getLocalOsfiles(q)
	if err != nil {
		return nil, err
	}
	return osfiles.Latest(q), nil
}

func LocalAppleDBQuery(q *ADBQuery) ([]AppleDBRecord, error) {
	osfiles, err := getLocalOsfiles(q)
	if err != nil {
		return nil, err
	}
	return osfiles.Query(q), nil
}

func AppleDBQuery(q *ADBQuery) ([]AppleDBRecord, error) {
	return queryAppleDBAPI(
		q,
		func(apiPath string) ([]GithubContentsResponse, error) {
			return queryGithubAPI(apiPath, q.Proxy, q.APIToken, q.Insecure)
		},
		func(filePath string) (*AppleDbOsFile, error) {
			return getOsFiles(filePath, q.Proxy, q.APIToken, q.Insecure)
		},
	)
}

func queryAppleDBAPI(
	q *ADBQuery,
	list func(string) ([]GithubContentsResponse, error),
	read func(string) (*AppleDbOsFile, error),
) ([]AppleDBRecord, error) {
	var osfiles OsFiles
	for _, osFamily := range q.OSes {
		root := apiAppleDBOSRoot(osFamily, q.Type)
		folders, err := list(root)
		if err != nil {
			return nil, err
		}
		for _, folder := range folders {
			if folder.Type != "dir" || !appleDBReleaseFolderMatches(folder.Name, q) {
				continue
			}
			files, err := list(folder.Path)
			if err != nil {
				return nil, err
			}
			for _, file := range files {
				if file.Type != "file" || path.Ext(file.Path) != ".json" {
					continue
				}
				osfile, err := read(file.Path)
				if err != nil {
					log.WithError(err).Errorf("failed to download %s", path.Base(file.Path))
					continue
				}
				if prepareAppleDBOSFile(osfile, osFamily, q.Type) {
					osfiles = append(osfiles, *osfile)
				}
			}
		}
	}
	return osfiles.Query(q), nil
}

func localAppleDBOSRoot(repo, osFamily, sourceType string) string {
	if sourceType == "rsr" {
		return filepath.Join(repo, "osFiles", "Rapid Security Responses", osFamily)
	}
	return filepath.Join(repo, "osFiles", osFamily)
}

func apiAppleDBOSRoot(osFamily, sourceType string) string {
	if sourceType == "rsr" {
		return path.Join("osFiles", "Rapid Security Responses", osFamily)
	}
	return path.Join("osFiles", osFamily)
}

func appleDBReleaseFolderMatches(folder string, q *ADBQuery) bool {
	build, version, found := strings.Cut(folder, " - ")
	if !found {
		return false
	}
	if q.Version != "" && !strings.HasPrefix(q.Version, strings.TrimSuffix(version, "x")) {
		return false
	}
	return q.Build == "" || strings.HasPrefix(q.Build, strings.TrimSuffix(build, "x"))
}

func prepareAppleDBOSFile(osfile *AppleDbOsFile, osFamily, sourceType string) bool {
	if osfile.Internal {
		return false
	}
	osfile.canonicalOS = osFamily
	if sourceType == "rsr" {
		for idx := range osfile.Sources {
			osfile.Sources[idx].Type = "rsr"
		}
	}
	return true
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
