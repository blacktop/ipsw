package download

import (
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/gocolly/colly/v2"
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
	Devices []string `json:"devices,omitempty"`
	Version string   `json:"version,omitempty"`
	BuildID string   `json:"buildid,omitempty"`
}

type Keys map[string]string
type BuildKeys map[string]Keys
type DeviceKeys map[string]BuildKeys

func trimQuotes(s string) string {
	if len(s) > 0 && s[0] == '"' {
		s = s[1:]
	}
	if len(s) > 0 && s[len(s)-1] == '"' {
		s = s[:len(s)-1]
	}
	return s
}

func appendIfMissing(slice []string, i string) []string {
	for _, ele := range slice {
		if ele == i {
			return slice
		}
	}
	return append(slice, i)
}

// ScrapeURLs will scrape the iPhone Wiki for beta firmwares
func ScrapeURLs(build string) (map[string]BetaIPSW, error) {
	ipsws := map[string]BetaIPSW{}

	c := colly.NewCollector(
		colly.AllowedDomains("www.theiphonewiki.com"),
		colly.URLFilters(
			regexp.MustCompile("https://www.theiphonewiki.com/wiki/Beta_Firmware/(.+)$"),
		),
		colly.Async(true),
		colly.MaxDepth(1),
	)

	// On every a element which has href attribute call callback
	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		c.Visit(e.Request.AbsoluteURL(e.Attr("href")))
	})

	c.OnHTML("body", func(e *colly.HTMLElement) {
		e.ForEach("table.wikitable", func(_ int, ta *colly.HTMLElement) {
			var cols []string
			possibleIPSW := BetaIPSW{Devices: []string{}}

			ta.ForEach("tr", func(_ int, row *colly.HTMLElement) {
				row.ForEach("th", func(_ int, el *colly.HTMLElement) {
					cols = append(cols, trimQuotes(strings.TrimSpace(el.Text)))
				})
				row.ForEach("td", func(_ int, el *colly.HTMLElement) {
					switch cols[el.Index] {
					case "Version":
						possibleIPSW.Version = strings.TrimSpace(el.Text)
					case "Build":
						possibleIPSW.BuildID = strings.TrimSpace(el.Text)
					case "Keys":
						el.ForEach("a", func(_ int, device *colly.HTMLElement) {
							possibleIPSW.Devices = appendIfMissing(possibleIPSW.Devices, strings.TrimSpace(device.Text))
						})
					}

					if el.ChildAttr("a", "class") == "external text" {
						link := el.ChildAttr("a", "href")

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
									if _, ok := ipsws[link]; ok {
										oldIPSW := ipsws[link]
										for _, dev := range possibleIPSW.Devices {
											oldIPSW.Devices = appendIfMissing(oldIPSW.Devices, dev)
										}
										sort.Strings(oldIPSW.Devices)
										ipsws[link] = oldIPSW
									} else {
										ipsws[link] = possibleIPSW
									}
								}
							}
						}
					}
				})
			})
		})
	})

	for _, device := range devices {
		err := c.Visit("https://www.theiphonewiki.com/wiki/Beta_Firmware/" + device)
		if err != nil {
			return nil, errors.Wrap(err, "failed to scrape "+iphoneWikiURL)
		}
	}

	c.Wait()

	return ipsws, nil
}

// ScrapeKeys will scrape the iPhone Wiki for firmware keys
func ScrapeKeys(version string) (map[string]map[string]map[string]string, error) {
	keys := make(map[string]map[string]map[string]string, 1000)

	c := colly.NewCollector(
		colly.AllowedDomains("www.theiphonewiki.com"),
		colly.URLFilters(
			regexp.MustCompile("https://www.theiphonewiki.com/wiki/(.+)$"),
		),
		// colly.Async(true),
		colly.MaxDepth(1),
		colly.UserAgent("free0"),
		colly.IgnoreRobotsTxt(),
	)

	// On every a element which has href attribute call callback
	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		if strings.Contains(e.Attr("href"), "/wiki/") && !strings.Contains(e.Attr("href"), "redlink=1") {
			c.Visit(e.Request.AbsoluteURL(e.Attr("href")))
		}
	})

	c.OnHTML("body", func(e *colly.HTMLElement) {
		e.ForEach("code", func(_ int, code *colly.HTMLElement) {
			if len(code.Attr("id")) > 0 {
				if strings.Contains(code.Attr("id"), "-iv") || strings.Contains(code.Attr("id"), "-key") {
					if code.Text != "Unknown" {
						urlParts := strings.Split(code.Request.URL.Path, "_")
						buildID := urlParts[1]
						deviceID := strings.Trim(urlParts[2], "()")
						if keys[deviceID] == nil {
							keys[deviceID] = map[string]map[string]string{}
						}
						if keys[deviceID][buildID] == nil {
							keys[deviceID][buildID] = map[string]string{}
						}
						keys[deviceID][buildID][strings.TrimPrefix(code.Attr("id"), "keypage-")] = code.Text
						// fmt.Printf("%#v\n", keys[deviceID])
					}

				}
			}
		})
	})

	// Set error handler
	// c.OnError(func(r *colly.Response, err error) {
	// 	// fmt.Println("Request URL:", r.Request.URL, "failed with response:", r, "\nError:", err)
	// 	fmt.Println("Error:", err)
	// })

	c.SetRequestTimeout(60 * time.Second)

	// for _, v := range []string{"1.x", "2.x", "3.x", "4.x", "5.x", "6.x", "7.x", "8.x", "9.x", "10.x", "11.x", "12.x", "13.x", "14.x"} {
	for _, v := range []string{"13.x", "14.x"} {
		err := c.Visit("https://www.theiphonewiki.com/wiki/Firmware_Keys/" + v)
		if err != nil {
			return nil, errors.Wrap(err, "failed to scrape https://www.theiphonewiki.com/wiki/Firmware_Keys/"+v)
		}
	}

	c.Wait()

	return keys, nil
}
