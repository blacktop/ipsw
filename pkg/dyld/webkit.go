package dyld

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gocolly/colly/v2"
)

const webkitURL = "https://trac.webkit.org/browser/webkit/tags/"

func trimFirstRune(s string) string {
	_, i := utf8.DecodeRuneInString(s)
	return s[i:]
}

func ScrapeWebKitTRAC(version string) (string, string, error) {

	var changeset string

	c := colly.NewCollector(
		colly.MaxDepth(1),
	)

	// On every a element which has href attribute call callback
	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		link := e.Attr("href")

		if strings.Contains(link, "/log/webkit/tags/Safari-") {
			r := regexp.MustCompile(`\/Safari-(?P<version>(\d+\.)?(\d+\.)?(\d+\.)?(\d+\.)(\*|\d+))\?rev=(?P<changeset>\d+)$`)
			names := r.SubexpNames()

			result := r.FindAllStringSubmatch(link, -1)
			if result != nil {
				m := map[string]string{}
				for i, n := range result[0] {
					m[names[i]] = n
				}

				if strings.Contains(m["version"], trimFirstRune(version)) {
					changeset = e.Text
					version = trimFirstRune(version)
				}
			}
		} else if strings.Contains(link, "/log/webkit/tags/WebKit-") {
			r := regexp.MustCompile(`\/WebKit-(?P<version>(\d+\.)?(\d+\.)?(\d+\.)?(\d+\.)(\*|\d+))\?rev=(?P<changeset>\d+)$`)
			names := r.SubexpNames()

			result := r.FindAllStringSubmatch(link, -1)
			if result != nil {
				m := map[string]string{}
				for i, n := range result[0] {
					m[names[i]] = n
				}
				if strings.Contains(m["version"], version) {
					changeset = e.Text
				}
			}
		}
	})

	// Set error handler
	c.OnError(func(r *colly.Response, err error) {
		fmt.Println("Request URL:", r.Request.URL, "failed with response:", r, "\nError:", err)
	})

	c.SetRequestTimeout(60 * time.Second)
	c.Visit(webkitURL)

	if len(changeset) > 0 {
		return version, changeset, nil
	}

	return version, "", fmt.Errorf("failed to find svn rev for version: %s", version)
}
