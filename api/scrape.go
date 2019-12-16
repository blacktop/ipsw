package api

import (
	"regexp"
	"strings"

	"github.com/gocolly/colly"
	"github.com/pkg/errors"
)

const (
	iphoneWikiURL    = "https://www.theiphonewiki.com"
	firmwarePath     = "/wiki/Firmware"
	betaFirmwarePath = "/wiki/Beta_Firmware"
)

var devices = []string{"iPad", "iPad_Air", "iPad_Pro", "iPad_mini", "iPhone", "iPod_touch"}

// BetaIPSW object
type BetaIPSW struct {
	Device  string `json:"device,omitempty"`
	Version string `json:"version,omitempty"`
	BuildID string `json:"buildid,omitempty"`
	URL     string `json:"url,omitempty"`
}

func unique(ipsws []BetaIPSW) []BetaIPSW {
	unique := make(map[string]bool, len(ipsws))
	us := make([]BetaIPSW, len(unique))
	for _, elem := range ipsws {
		if len(elem.URL) != 0 {
			if !unique[elem.URL] {
				us = append(us, elem)
				unique[elem.URL] = true
			}
		}
	}
	return us
}

// ScrapeURLs will scrape the iPhone Wiki for beta firmwares
func ScrapeURLs(build string) ([]BetaIPSW, error) {
	ipsws := []BetaIPSW{}

	c := colly.NewCollector(
		colly.AllowedDomains("www.theiphonewiki.com"),
		colly.URLFilters(
			regexp.MustCompile("https://www.theiphonewiki.com/wiki/Beta_Firmware/(.+)$"),
		),
		colly.Async(true),
	)

	// On every a element which has href attribute call callback
	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		link := e.Attr("href")

		if strings.Contains(link, "apple.com") {
			r := regexp.MustCompile(`\/(?P<device>i.+)_(?P<version>.+)_(?P<build>\w+)_Restore.ipsw$`)
			names := r.SubexpNames()

			result := r.FindAllStringSubmatch(link, -1)
			if result != nil {
				m := map[string]string{}
				for i, n := range result[0] {
					m[names[i]] = n
				}
				if strings.EqualFold(m["build"], build) {
					ipsws = append(ipsws, BetaIPSW{
						Device:  m["device"],
						Version: m["version"],
						BuildID: m["build"],
						URL:     link,
					})
				}
			}
		}

		c.Visit(e.Request.AbsoluteURL(link))
	})

	for _, device := range devices {
		err := c.Visit("https://www.theiphonewiki.com/wiki/Beta_Firmware/" + device)
		if err != nil {
			return nil, errors.Wrap(err, "failed to scrape "+iphoneWikiURL)
		}
	}

	c.Wait()

	return unique(ipsws), nil
}
