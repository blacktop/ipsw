package download

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/apex/log"
)

const (
	// SecurityIndexURL is Apple's table of security releases.
	SecurityIndexURL        = "https://support.apple.com/en-us/100100"
	securityAdvisoryJSONURL = "https://support.apple.com/content/dam/edam/applecare/images/en_US/otherassets/security/%s.json"
	securityIndexDateLayout = "2 Jan 2006"
	maxSecurityResponseSize = 32 << 20
)

// securityFirstJSONRelease is the release date of the first advisories Apple
// published with a CSAF JSON download. Older advisories only exist as HTML.
var securityFirstJSONRelease = time.Date(2026, time.September, 14, 0, 0, 0, 0, time.UTC)

var securityAdvisoryIDPattern = regexp.MustCompile(`^[0-9]+$`)

// ErrSecurityAdvisoryNotFound means Apple has no JSON for an advisory.
var ErrSecurityAdvisoryNotFound = errors.New("security advisory JSON not found")

// SecurityStatusError is an unexpected HTTP status for one advisory request.
type SecurityStatusError struct {
	Advisory   string
	StatusCode int
	Attempts   int
}

func (e *SecurityStatusError) Error() string {
	if e.Attempts > 1 {
		return fmt.Sprintf("security advisory %s: HTTP %d after %d attempts", e.Advisory, e.StatusCode, e.Attempts)
	}
	return fmt.Sprintf("security advisory %s: HTTP %d", e.Advisory, e.StatusCode)
}

// SecurityIndexEntry is one row of Apple's security releases table. ID is empty
// for releases with no published CVE entries.
type SecurityIndexEntry struct {
	ID          string
	Name        string
	URL         string
	ReleaseDate time.Time
}

// ExpectsJSON reports whether the entry links an advisory released on or after
// the first CSAF JSON release. Some of those still have no JSON and return 404.
func (e SecurityIndexEntry) ExpectsJSON() bool {
	return e.ID != "" && !e.ReleaseDate.Before(securityFirstJSONRelease)
}

// CSAFAdvisory holds the parts of an Apple CSAF 2.1 advisory the watcher reads.
type CSAFAdvisory struct {
	Vulnerabilities []CSAFVulnerability `json:"vulnerabilities"`
}

// CSAFVulnerability is one CVE entry in an advisory.
type CSAFVulnerability struct {
	CVE             string               `json:"cve"`
	Title           string               `json:"title"`
	Notes           []CSAFNote           `json:"notes"`
	ProductStatus   CSAFProductStatus    `json:"product_status"`
	Acknowledgments []CSAFAcknowledgment `json:"acknowledgments"`
}

// CSAFNote is a categorized vulnerability note.
type CSAFNote struct {
	Category string `json:"category"`
	Text     string `json:"text"`
}

// CSAFProductStatus lists the product IDs a vulnerability is fixed in.
type CSAFProductStatus struct {
	Fixed []string `json:"fixed"`
}

// CSAFAcknowledgment lists credited finders. Apple's organization field is
// unreliable, so only names are decoded.
type CSAFAcknowledgment struct {
	Names []string `json:"names"`
}

// Note returns the text of the first note with the given category.
func (v CSAFVulnerability) Note(category string) string {
	for _, note := range v.Notes {
		if note.Category == category {
			return note.Text
		}
	}
	return ""
}

// CreditNames returns every acknowledged name in document order.
func (v CSAFVulnerability) CreditNames() []string {
	var names []string
	for _, ack := range v.Acknowledgments {
		names = append(names, ack.Names...)
	}
	return names
}

// SecurityAdvisoryResponse is the result of a conditional advisory request.
type SecurityAdvisoryResponse struct {
	NotModified  bool
	ETag         string
	LastModified string
	Advisory     *CSAFAdvisory
}

// SecurityClient fetches Apple's security index and advisory JSON. It spaces
// requests MinInterval apart and retries HTTP 429 after each Backoff delay.
// It is not safe for concurrent use.
type SecurityClient struct {
	HTTP        *http.Client
	MinInterval time.Duration
	Backoff     []time.Duration
	lastRequest time.Time
}

// NewSecurityClient returns a client paced for support.apple.com, which throttles
// the JSON paths for 10+ minutes after bursts of requests.
func NewSecurityClient(client *http.Client) *SecurityClient {
	return &SecurityClient{
		HTTP:        client,
		MinInterval: 3 * time.Second,
		Backoff: []time.Duration{
			30 * time.Second,
			time.Minute,
			2 * time.Minute,
			4 * time.Minute,
			8 * time.Minute,
		},
	}
}

// Index fetches and parses Apple's security releases table.
func (c *SecurityClient) Index(ctx context.Context) ([]SecurityIndexEntry, error) {
	resp, attempts, err := c.get(ctx, SecurityIndexURL, nil)
	if err != nil {
		return nil, err
	}
	defer drainAndClose(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned HTTP %d after %d attempt(s)", SecurityIndexURL, resp.StatusCode, attempts)
	}
	return ParseSecurityIndex(io.LimitReader(resp.Body, maxSecurityResponseSize))
}

// Advisory fetches one advisory's JSON. A non-empty etag or lastModified makes
// the request conditional; a 304 returns NotModified with no Advisory.
func (c *SecurityClient) Advisory(ctx context.Context, id, etag, lastModified string) (SecurityAdvisoryResponse, error) {
	header := http.Header{}
	if etag != "" {
		header.Set("If-None-Match", etag)
	}
	if lastModified != "" {
		header.Set("If-Modified-Since", lastModified)
	}
	resp, attempts, err := c.get(ctx, fmt.Sprintf(securityAdvisoryJSONURL, id), header)
	if err != nil {
		return SecurityAdvisoryResponse{}, fmt.Errorf("security advisory %s: %w", id, err)
	}
	defer drainAndClose(resp.Body)

	result := SecurityAdvisoryResponse{
		ETag:         headerOr(resp.Header, "ETag", etag),
		LastModified: headerOr(resp.Header, "Last-Modified", lastModified),
	}
	switch resp.StatusCode {
	case http.StatusOK:
		var advisory CSAFAdvisory
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxSecurityResponseSize)).Decode(&advisory); err != nil {
			return SecurityAdvisoryResponse{}, fmt.Errorf("security advisory %s: failed to decode JSON: %w", id, err)
		}
		result.Advisory = &advisory
		return result, nil
	case http.StatusNotModified:
		result.NotModified = true
		return result, nil
	case http.StatusNotFound:
		return SecurityAdvisoryResponse{}, fmt.Errorf("security advisory %s: %w", id, ErrSecurityAdvisoryNotFound)
	default:
		return SecurityAdvisoryResponse{}, &SecurityStatusError{Advisory: id, StatusCode: resp.StatusCode, Attempts: attempts}
	}
}

func (c *SecurityClient) get(ctx context.Context, target string, header http.Header) (*http.Response, int, error) {
	for attempt := 1; ; attempt++ {
		if err := c.pace(ctx); err != nil {
			return nil, attempt, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, attempt, fmt.Errorf("failed to create request for %s: %w", target, err)
		}
		if header != nil {
			req.Header = header.Clone()
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return nil, attempt, err
		}
		if resp.StatusCode != http.StatusTooManyRequests || attempt > len(c.Backoff) {
			return resp, attempt, nil
		}
		drainAndClose(resp.Body)
		delay := c.Backoff[attempt-1]
		log.Warnf("%s returned HTTP 429; retrying in %s", target, delay)
		if err := waitForContext(ctx, delay); err != nil {
			return nil, attempt, err
		}
	}
}

func (c *SecurityClient) pace(ctx context.Context) error {
	if wait := c.MinInterval - time.Since(c.lastRequest); wait > 0 {
		if err := waitForContext(ctx, wait); err != nil {
			return err
		}
	}
	c.lastRequest = time.Now()
	return nil
}

// drainAndClose reads the rest of a body so its HTTP/1.1 connection is reused.
func drainAndClose(body io.ReadCloser) {
	io.Copy(io.Discard, io.LimitReader(body, maxSecurityResponseSize))
	body.Close()
}

func headerOr(header http.Header, key, fallback string) string {
	if value := header.Get(key); value != "" {
		return value
	}
	return fallback
}

// ParseSecurityIndex parses the rows of Apple's security releases table.
func ParseSecurityIndex(r io.Reader) ([]SecurityIndexEntry, error) {
	doc, err := goquery.NewDocumentFromReader(r)
	if err != nil {
		return nil, fmt.Errorf("failed to parse security index HTML: %w", err)
	}
	var entries []SecurityIndexEntry
	for _, row := range doc.Find("table tr").EachIter() {
		cells := row.Find("td")
		if cells.Length() < 3 {
			continue
		}
		entry, err := parseSecurityIndexRow(cells)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no releases found in %s; the page layout may have changed", SecurityIndexURL)
	}
	return entries, nil
}

func parseSecurityIndexRow(cells *goquery.Selection) (SecurityIndexEntry, error) {
	nameCell := cells.Eq(0)
	dateText := collapseSpace(cells.Eq(2).Text())
	date, err := time.Parse(securityIndexDateLayout, dateText)
	if err != nil {
		return SecurityIndexEntry{}, fmt.Errorf(
			"failed to parse release date %q for %q in security index: %w",
			dateText, collapseSpace(nameCell.Text()), err,
		)
	}
	entry := SecurityIndexEntry{ReleaseDate: date}
	link := nameCell.Find("a[href]").First()
	if link.Length() == 0 {
		entry.Name = collapseSpace(nameCell.Find("p").First().Text())
		return entry, nil
	}
	entry.Name = collapseSpace(link.Text())
	entry.URL, _ = link.Attr("href")
	entry.ID = securityAdvisoryID(entry.URL)
	return entry, nil
}

func securityAdvisoryID(link string) string {
	parsed, err := url.Parse(link)
	if err != nil {
		return ""
	}
	id := path.Base(parsed.Path)
	if !securityAdvisoryIDPattern.MatchString(id) {
		return ""
	}
	return id
}

func collapseSpace(text string) string {
	return strings.Join(strings.Fields(text), " ")
}
