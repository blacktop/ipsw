//go:build !ios

package download

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// devPortalCookie records the source needed to replay SetCookies without
// guessing the domain, path, or lifetime stripped by Jar.Cookies.
type devPortalCookie struct {
	URL    string      `json:"url"`
	Cookie http.Cookie `json:"cookie"`
}

func (r devPortalCookie) domain() string {
	if r.Cookie.Domain != "" {
		return strings.ToLower(strings.TrimPrefix(r.Cookie.Domain, "."))
	}
	origin, _ := url.Parse(r.URL) // Records are created from parsed URLs.
	return strings.ToLower(strings.TrimSuffix(origin.Hostname(), "."))
}

type devPortalCookieJar struct {
	*cookiejar.Jar
	mu      sync.Mutex
	records []devPortalCookie
}

func newDevPortalCookieJar() (*devPortalCookieJar, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &devPortalCookieJar{Jar: jar}, nil
}

func (j *devPortalCookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.expireRecords()
	if u.Scheme != "http" && u.Scheme != "https" {
		return
	}
	// Strip query strings and userinfo; replay needs only the source origin.
	origin := (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/"}).String()
	for _, cookie := range cookies {
		saved := *cookie
		saved.Unparsed = slices.Clone(cookie.Unparsed)
		if saved.Path == "" || saved.Path[0] != '/' {
			saved.Path = "/"
			if i := strings.LastIndex(u.Path, "/"); i > 0 {
				saved.Path = u.Path[:i]
			}
		}
		// Let the standard jar validate domain/scheme rules, including deletions,
		// before a rejected cookie can alter the persisted scope record.
		probe, _ := cookiejar.New(nil)
		candidate := saved
		candidate.MaxAge, candidate.Expires = 0, time.Time{}
		probe.SetCookies(u, []*http.Cookie{&candidate})
		target := *u
		target.Path = saved.Path
		target.Scheme = "https" // Secure cookies may be accepted on an HTTP response.
		if len(probe.Cookies(&target)) == 0 {
			continue
		}
		if saved.MaxAge > 0 {
			// MaxAge is relative to receipt, not the next process's login attempt.
			saved.Expires = time.Now().Add(time.Duration(saved.MaxAge) * time.Second)
			saved.MaxAge = 0
		}
		j.Jar.SetCookies(u, []*http.Cookie{&saved})
		record := devPortalCookie{URL: origin, Cookie: saved}
		domain := record.domain()
		index := slices.IndexFunc(j.records, func(old devPortalCookie) bool {
			return old.domain() == domain && old.Cookie.Name == saved.Name && old.Cookie.Path == saved.Path
		})
		if saved.MaxAge < 0 || (!saved.Expires.IsZero() && !saved.Expires.After(time.Now())) {
			if index >= 0 {
				j.records = slices.Delete(j.records, index, index+1)
			}
			continue
		}
		if index >= 0 {
			j.records[index] = record
		} else {
			j.records = append(j.records, record)
		}
	}
}

// Drop expired records before reissuing a cookie, so replay preserves the new
// cookie's creation order relative to overlapping host/domain cookies.
// The caller holds mu.
func (j *devPortalCookieJar) expireRecords() {
	now := time.Now()
	j.records = slices.DeleteFunc(j.records, func(record devPortalCookie) bool {
		if record.Cookie.Expires.IsZero() || record.Cookie.Expires.After(now) {
			return false
		}
		origin, _ := url.Parse(record.URL)
		cookie := record.Cookie
		cookie.MaxAge = -1
		j.Jar.SetCookies(origin, []*http.Cookie{&cookie})
		return true
	})
}

func (j *devPortalCookieJar) snapshot() []devPortalCookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.expireRecords()
	records := slices.Clone(j.records)
	for i := range records {
		records[i].Cookie.Unparsed = slices.Clone(records[i].Cookie.Unparsed)
	}
	return records
}
