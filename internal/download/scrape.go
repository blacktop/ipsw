package download

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/gocolly/colly/v2"
	"github.com/pkg/errors"
)

const (
	iphoneWikiURL                  = "www.theiphonewiki.com"
	iphoneWikiOtaUrlRegex          = "^https://www.theiphonewiki.com/wiki/OTA_Updates/(.+)$"
	iphoneWikiBetaOtaUrlRegex      = "^https://www.theiphonewiki.com/wiki/Beta_OTA_Updates/(.+)$"
	iphoneWikiFirmwareUrlRegex     = "^https://www.theiphonewiki.com/wiki/Firmware/(.+)$"
	iphoneWikiBetaFirmwareUrlRegex = "^https://www.theiphonewiki.com/wiki/Beta_Firmware/(.+)$"
)

var devices = []string{"iPad", "iPad_Air", "iPad_Pro", "iPad_mini", "iPhone", "iPod_touch", "Apple_Watch", "Mac", "HomePod"}
var deviceMap = map[string][]string{ // FIXME: this is incomplete (NOTE: iPhoneSE maps to iPhone8,4 but so does iPhone_4.0_64bit ???)
	"iPad8,11,iPad8,12":                {"iPad8,12", "iPad8,11"},
	"iPadPro_12.9":                     {"iPad6,7", "iPad6,8"},
	"iPadPro_9.7":                      {"iPad6,3", "iPad6,4"},
	"iPad_10.2":                        {"iPad7,12", "iPad7,11"},
	"iPad_10.2_2020":                   {"iPad11,6", "iPad11,7"},
	"iPad_10.2_2021":                   {"iPad12,1", "iPad12,2"},
	"iPad_32bit":                       {"iPad3,4", "iPad3,5", "iPad3,6"},
	"iPad_64bit":                       {"iPad4,4", "iPad4,5", "iPad4,2", "iPad4,6", "iPad4,3", "iPad4,1"},
	"iPad_64bit_TouchID":               {"iPad5,1", "iPad5,2", "iPad5,3", "iPad4,8", "iPad4,7", "iPad4,9", "iPad5,4"},
	"iPad_64bit_TouchID_ASTC":          {"iPad6,11", "iPad6,12"},
	"iPad_Educational":                 {"iPad7,12", "iPad7,11"},
	"iPad_Educational_2020":            {"iPad11,6", "iPad11,7"},
	"iPad_Fall_2018":                   {"iPad8,7", "iPad8,6", "iPad8,5", "iPad8,4", "iPad8,3", "iPad8,2", "iPad8,1", "iPad8,8"},
	"iPad_Fall_2020":                   {"iPad13,1", "iPad13,2"},
	"iPad_Fall_2021":                   {"iPad14,2", "iPad14,1"},
	"iPad_Pro_A12X_A12Z":               {"iPad8,7", "iPad8,6", "iPad8,5", "iPad8,4", "iPad8,3", "iPad8,2", "iPad8,1", "iPad8,9", "iPad8,8", "iPad8,12", "iPad8,11", "iPad8,10"},
	"iPad_Pro_HFR":                     {"iPad7,1", "iPad7,2", "iPad7,3", "iPad7,4"},
	"iPad_Pro_Spring_2021":             {"iPad13,10", "iPad13,11", "iPad13,8", "iPad13,9", "iPad13,4", "iPad13,5", "iPad13,6", "iPad13,7"},
	"iPad_Spring_2019":                 {"iPad11,2", "iPad11,3", "iPad11,1", "iPad11,4"},
	"iPad_Spring_2020":                 {"iPad8,10", "iPad8,9"},
	"iPhone":                           {"iPhone12,1"},
	"iPhone10,3,iPhone10,6":            {"iPhone10,6", "iPhone10,3"},
	"iPhone10,4":                       {"iPhone10,4", "iPhone10,1"},
	"iPhone10,5":                       {"iPhone10,5", "iPhone10,2"},
	"iPhone11,2,iPhone11,4,iPhone11,6": {"iPhone11,6", "iPhone11,4", "iPhone11,2"},
	"iPhone11,2,iPhone11,4,iPhone11,6,iPhone12,3,iPhone12,5": {"iPhone11,6", "iPhone11,4", "iPhone11,2", "iPhone12,5", "iPhone12,3"},
	"iPhone11,4,iPhone11,6":                                  {"iPhone11,6", "iPhone11,4"},
	"iPhone11,8,iPhone12,1":                                  {"iPhone12,1", "iPhone11,8"},
	"iPhone12,3,iPhone12,5":                                  {"iPhone12,5", "iPhone12,3"},
	"iPhone13,2,iPhone13,3":                                  {"iPhone13,3", "iPhone13,2"},
	"iPhone9,1":                                              {"iPhone9,1", "iPhone9,3"},
	"iPhone9,2":                                              {"iPhone9,2", "iPhone9,4"},
	"iPhoneSE":                                               {"iPhone8,4"},
	"iPhone_4.0_32bit":                                       {"iPhone5,2", "iPhone5,4", "iPhone5,3", "iPhone5,1"},
	"iPhone_4.0_64bit":                                       {"iPhone6,2", "iPhone6,1"},
	"iPhone_4.7":                                             {"iPhone8,1", "iPhone7,2"},
	"iPhone_4.7_P3":                                          {"iPhone10,4", "iPhone9,1", "iPhone9,3", "iPhone10,1"},
	"iPhone_5.5":                                             {"iPhone8,2", "iPhone7,1"},
	"iPhone_5.5_P3":                                          {"iPhone9,4", "iPhone10,5", "iPhone10,2", "iPhone9,2"},
	"iPhone_7":                                               {"iPhone9,3", "iPhone9,1"},
	"iPhone_7Plus":                                           {"iPhone9,4", "iPhone9,2"},
	"iPodtouch":                                              {"iPod7,1"},
	"iPodtouch_7":                                            {"iPod9,1"},
}

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
	if slices.Contains(slice, i) {
		return slice
	}
	return append(slice, i)
}

func GenerateDeviceMap(urls []string) {
	name2devs := make(map[string][]string)
	for _, b := range []string{"11A465", "12A365", "13A344", "14A403", "15A372", "16A366", "17A577", "18A373", "19A346"} {
		for _, ipsw := range FilterIpswURLs(urls, "", "", b) {
			d, _, _ := ParseIpswURLString(ipsw)
			if len(d) > 0 {
				if _, ok := name2devs[d]; !ok {
					zr, err := NewRemoteZipReader(ipsw, &RemoteConfig{})
					if err != nil {
						// return errors.Wrap(err, "failed to create new remote zip reader")
						continue
					}
					ii, err := info.ParseZipFiles(zr.File)
					if err != nil {
						// return errors.Wrap(err, "failed to extract remote plists")
						continue
					}
					name2devs[d] = ii.Plists.BuildManifest.SupportedProductTypes
				}
			}
		}
	}
	keys := make([]string, 0, len(name2devs))
	for k := range name2devs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if len(name2devs[k]) > 1 {
			fmt.Printf("\"%s\": %#v,\n", k, name2devs[k])
		} else {
			if name2devs[k][0] != k {
				fmt.Printf("\"%s\": %#v,\n", k, name2devs[k])
			}
		}
	}
}

func ParseIpswURLString(url string) (string, string, string) {
	re := regexp.MustCompile(`^.*/(?P<device>.+)_(?P<version>.+)_(?P<build>.+)_Restore\.ipsw$`)
	if re.MatchString(url) {
		matches := re.FindStringSubmatch(url)
		return matches[1], matches[2], matches[3]
	}
	return "", "", ""
}

func FilterIpswURLs(urls []string, device, version, build string) []string {
	var filteredUrls []string
	if len(device) == 0 {
		device = ".*"
	} else {
		for name, devices := range deviceMap {
			if utils.StrSliceHas(devices, device) {
				device = name
				break
			}
		}
	}
	if len(version) == 0 {
		version = ".*"
	}
	if len(build) == 0 {
		build = ".*"
	}
	re := regexp.MustCompile(fmt.Sprintf("/%s_%s_%s_Restore.ipsw$", device, version, build))
	for _, url := range urls {
		if re.MatchString(url) {
			filteredUrls = append(filteredUrls, url)
		}
	}
	return filteredUrls
}

func ScrapeIPSWs(beta bool) ([]string, error) {
	var ipsws []string

	c := colly.NewCollector(
		colly.AllowedDomains(iphoneWikiURL),
		colly.URLFilters(
			regexp.MustCompile(iphoneWikiFirmwareUrlRegex),
			regexp.MustCompile(iphoneWikiBetaFirmwareUrlRegex),
		),
		colly.Async(true),
		colly.MaxDepth(1),
	)

	// On every a element which has href attribute call callback
	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		c.Visit(e.Request.AbsoluteURL(e.Attr("href")))
	})

	c.OnHTML("body", func(e *colly.HTMLElement) {
		e.ForEach("a[href]", func(_ int, e *colly.HTMLElement) {
			if strings.Contains(e.Text, ".ipsw") && !strings.Contains(e.Text, "download.developer.apple.com") {
				ipsws = append(ipsws, e.Request.AbsoluteURL(e.Attr("href")))
			}
		})
	})

	for _, device := range devices {
		if beta {
			if err := c.Visit("https://www.theiphonewiki.com/wiki/Beta_Firmware/" + device); err != nil {
				return nil, errors.Wrap(err, "failed to scrape "+iphoneWikiURL)
			}
		} else {
			if err := c.Visit("https://www.theiphonewiki.com/wiki/Firmware/" + device); err != nil {
				return nil, errors.Wrap(err, "failed to scrape "+iphoneWikiURL)
			}
		}
	}

	c.Wait()

	if len(ipsws) == 0 {
		return nil, fmt.Errorf("no IPSWs found")
	}

	return utils.Unique(ipsws), nil
}

func ScrapeOTAs(beta bool) ([]string, error) {
	var otas []string

	c := colly.NewCollector(
		colly.AllowedDomains(iphoneWikiURL),
		colly.URLFilters(
			regexp.MustCompile(iphoneWikiOtaUrlRegex),
			regexp.MustCompile(iphoneWikiBetaOtaUrlRegex),
		),
		colly.Async(true),
		colly.MaxDepth(1),
	)

	// On every a element which has href attribute call callback
	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		c.Visit(e.Request.AbsoluteURL(e.Attr("href")))
	})

	c.OnHTML("body", func(e *colly.HTMLElement) {
		e.ForEach("a[href]", func(_ int, e *colly.HTMLElement) {
			if strings.Contains(e.Text, ".zip") {
				otas = append(otas, e.Request.AbsoluteURL(e.Attr("href")))
			}
		})
	})

	for _, device := range devices {
		if beta {
			if err := c.Visit("https://www.theiphonewiki.com/wiki/Beta_OTA_Updates/" + device); err != nil {
				return nil, errors.Wrap(err, "failed to scrape "+iphoneWikiURL)
			}
		} else {
			if err := c.Visit("https://www.theiphonewiki.com/wiki/OTA_Updates/" + device); err != nil {
				return nil, errors.Wrap(err, "failed to scrape "+iphoneWikiURL)
			}
		}
	}

	c.Wait()

	if len(otas) == 0 {
		return nil, fmt.Errorf("no OTAs found")
	}

	return utils.Unique(otas), nil
}

// ScrapeURLs will scrape the iPhone Wiki for beta firmwares
func ScrapeURLs(build string) (map[string]BetaIPSW, error) {
	ipsws := map[string]BetaIPSW{}

	c := colly.NewCollector(
		colly.AllowedDomains(iphoneWikiURL),
		colly.URLFilters(
			regexp.MustCompile(iphoneWikiFirmwareUrlRegex),
			regexp.MustCompile(iphoneWikiBetaFirmwareUrlRegex),
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
		if err := c.Visit("https://www.theiphonewiki.com/wiki/Firmware/" + device); err != nil {
			return nil, errors.Wrap(err, "failed to scrape "+iphoneWikiURL)
		}
		if err := c.Visit("https://www.theiphonewiki.com/wiki/Beta_Firmware/" + device); err != nil {
			return nil, errors.Wrap(err, "failed to scrape "+iphoneWikiURL)
		}
	}

	c.Wait()

	if len(ipsws) == 0 {
		return nil, fmt.Errorf("no ipsws found for build %s", build)
	}

	return ipsws, nil
}

// ScrapeKeys will scrape the iPhone Wiki for firmware keys
func ScrapeKeys(version string) (map[string]map[string]map[string]string, error) {
	keys := make(map[string]map[string]map[string]string, 1000)

	c := colly.NewCollector(
		colly.AllowedDomains(iphoneWikiURL),
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
