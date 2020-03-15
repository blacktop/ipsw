package dyld

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gocolly/colly/v2"
)

const webkitURL = "https://trac.webkit.org/browser/webkit/tags/"

// GetWebKitVersion greps the dyld_shared_cache for the WebKit version string
func GetWebKitVersion(path string) (string, error) {

	fd, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer fd.Close()

	var re = regexp.MustCompile(`WebKit2-(\d+\.)?(\d+\.)?(\d+\.)?(\d+\.)(\*|\d+)`)
	var match string

	reader := bufio.NewReader(fd)

	line, err := reader.ReadString('\n')
	for err == nil {
		match = re.FindString(line)
		if len(match) > 0 {
			break
		}
		line, err = reader.ReadString('\n')
	}

	if err == io.EOF {
		return match, nil
	}

	if len(match) > 0 {
		version := strings.TrimPrefix(match, "WebKit2-")[1:]
		rev, err := scrapeWebKitTRAC(version)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s (svn rev %s)", version, rev), nil
	}

	return "", fmt.Errorf("unable to find WebKit version in file: %s", path)
}

func scrapeWebKitTRAC(version string) (string, error) {

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
				if strings.Contains(m["version"], version) {
					// changeset = m["changeset"]
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
		return changeset, nil
	}

	return "", fmt.Errorf("failed to find svn rev for version: %s", version)
}
