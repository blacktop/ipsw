package download

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/blacktop/ipsw/internal/utils"
)

const (
	iPhoneWikiAPI = "https://www.theiphonewiki.com/w/api.php"
)

type WikiIPSW struct {
	Version       string   `json:"version,omitempty"`
	Build         string   `json:"build,omitempty"`
	Devices       []string `json:"keys,omitempty"`
	Baseband      string   `json:"baseband,omitempty"`
	ReleaseDate   string   `json:"release_date,omitempty"`
	DownloadUrl   string   `json:"download_url,omitempty"`
	Sha1Hash      string   `json:"sha1,omitempty"`
	FileSize      int      `json:"file_size,omitempty"`
	Documentation string   `json:"doc,omitempty"`
}

type WikiOTA WikiIPSW

type wikiSection struct {
	TocLevel   int    `json:"toclevel,omitempty"`
	Level      string `json:"level,omitempty"`
	Line       string `json:"line,omitempty"`
	Number     string `json:"number,omitempty"`
	Index      string `json:"index,omitempty"`
	FromTitle  string `json:"from_title,omitempty"`
	ByteOffset int    `json:"byte_offset,omitempty"`
	Anchor     string `json:"anchor,omitempty"`
}

type wikiLink struct {
	NS     int    `json:"ns,omitempty"`
	Exists string `json:"exists,omitempty"`
	Link   string `json:"*,omitempty"`
}

type wikiCategory struct {
	SortKey string `json:"sortkey,omitempty"`
	Title   string `json:"*,omitempty"`
}

type wikiTemplate struct {
	NS     int    `json:"ns,omitempty"`
	Exists string `json:"exists,omitempty"`
	Link   string `json:"*,omitempty"`
}

type wikiText struct {
	Text string `json:"*,omitempty"`
}

type wikiParseData struct {
	Title         string         `json:"title,omitempty"`
	DisplayTitle  string         `json:"displaytitle,omitempty"`
	PageID        int            `json:"pageid,omitempty"`
	RevID         int            `json:"revid,omitempty"`
	Redirects     []string       `json:"redirects,omitempty"`
	Sections      []wikiSection  `json:"sections,omitempty"`
	Links         []wikiLink     `json:"links,omitempty"`
	LangLinks     []string       `json:"langlinks,omitempty"`
	Categories    []wikiCategory `json:"categories,omitempty"`
	Templates     []wikiTemplate `json:"templates,omitempty"`
	ExternalLinks []string       `json:"externallinks,omitempty"`
	WikiText      wikiText       `json:"wikitext,omitempty"`
}

type wikiParseResults struct {
	Parse wikiParseData `json:"parse"`
}

type wikiFWKeys struct {
	Version            string
	Build              string
	Device             string
	Codename           string
	Baseband           string
	DownloadURL        string
	RootFS             string
	RootFSKey          string
	UpdateRamdisk      string
	UpdateRamdiskIV    string
	RestoreRamdisk     string
	RestoreRamdiskIV   string
	AppleLogo          string
	AppleLogoIV        string
	BatteryCharging0   string
	BatteryCharging0IV string
	BatteryCharging1   string
	BatteryCharging1IV string
	BatteryFull        string
	BatteryFullIV      string
	BatteryLow0        string
	BatteryLow0IV      string
	BatteryLow1        string
	BatteryLow1IV      string
	DeviceTree         string
	DeviceTreeIV       string
	GlyphPlugin        string
	GlyphPluginIV      string
	IBEC               string
	IBECIV             string
	IBECKey            string
	IBoot              string
	IBootIV            string
	IBootKey           string
	IBSS               string
	IBSSIV             string
	IBSSKey            string
	Kernelcache        string
	KernelcacheIV      string
	LLB                string
	LLBIV              string
	LLBKey             string
	RecoveryMode       string
	RecoveryModeIV     string
	SEPFirmware        string
	SEPFirmwareIV      string
	SEPFirmwareKey     string
	SEPFirmwareKBAG    string
}

func getWikiPage(page string, proxy string, insecure bool) (*wikiParseResults, error) {
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           GetProxy(proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
	}

	req, err := http.NewRequest("GET", iPhoneWikiAPI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	q := req.URL.Query()
	q.Add("format", "json")
	q.Add("action", "parse")
	q.Add("page", page)
	q.Add("redirects", "true")
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get response: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get response: %s", resp.Status)
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// parse the response
	var parseResp wikiParseResults
	if err := json.Unmarshal(data, &parseResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &parseResp, nil
}

func getWikiTable(page string, proxy string, insecure bool) (*wikiParseResults, error) {
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           GetProxy(proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
	}

	req, err := http.NewRequest("GET", iPhoneWikiAPI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	q := req.URL.Query()
	q.Add("action", "parse")
	q.Add("page", page)
	q.Add("prop", "wikitext")
	// q.Add("section", "5")
	q.Add("redirects", "true")
	q.Add("format", "json")
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get response: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get response: %s", resp.Status)
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// parse the response
	var parseResp wikiParseResults
	if err := json.Unmarshal(data, &parseResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &parseResp, nil
}

func getRowOrColInc(line string) (int, int, string, error) {
	re := regexp.MustCompile(`rowspan="(?P<rinc>\d+)" ?(colspan="(?P<cinc>\d+)") (?P<field>.*)`)
	if re.MatchString(line) {
		matches := re.FindStringSubmatch(line)
		if len(matches) != 5 {
			return 0, 0, "", fmt.Errorf("failed to parse row/col span")
		}

		rinc, err := strconv.Atoi(matches[1])
		if err != nil {
			return 0, 0, "", fmt.Errorf("failed to parse row span: %w", err)
		}

		cinc, err := strconv.Atoi(matches[3])
		if err != nil {
			return 0, 0, "", fmt.Errorf("failed to parse col span: %w", err)
		}

		return rinc, cinc, matches[4], nil
	}
	return 0, 0, "", nil
}

// parse wikitable
func parseWikiTable(text string) ([]*WikiIPSW, error) {
	var results []*WikiIPSW

	fieldCount := 0
	headerCount := 0
	ipsw := &WikiIPSW{}
	index2Header := make(map[int]string)

	scanner := bufio.NewScanner(strings.NewReader(text))

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "==") {
			continue // skip header
		} else if strings.HasPrefix(line, "{|") {
			headerCount = 0
			index2Header = make(map[int]string)
			continue // skip table
		} else if strings.HasPrefix(line, "|-") {
			fieldCount = 0
			continue // skip table row delimiter
		} else if strings.HasPrefix(line, "! ") {
			line = strings.TrimPrefix(line, "! ")
			line = strings.TrimSpace(line)
			if strings.Contains(line, "rowspan") {
				line = strings.Split(line, "|")[1]
				line = strings.TrimSpace(line)
				index2Header[headerCount] = line
				headerCount++
			} else if strings.Contains(line, "colspan") {
				parts := strings.Split(line, "|")
				parts[0] = strings.TrimSpace(parts[0])
				colWidth := strings.TrimPrefix(parts[0], "colspan=\"")
				colWidth = strings.TrimSuffix(colWidth, "\"")
				inc, err := strconv.Atoi(colWidth)
				if err != nil {
					return nil, fmt.Errorf("failed to parse colspan: %s", err)
				}
				index2Header[headerCount] = strings.TrimSpace(parts[1])
				headerCount += inc
			} else {
				index2Header[headerCount] = line
				headerCount++
			}
		} else if strings.HasPrefix(line, "|}") {
			fieldCount = 0
			headerCount = 0
			index2Header = make(map[int]string)
			continue // skip table row
			// } else if strings.HasPrefix(line, "| ") && strings.Contains(line, "{{n/a}}") {
			// 	line = strings.TrimPrefix(line, "|")
			// 	line = strings.TrimSpace(line)
			// 	a, b, c, e := getRowOrColInc(line)
			// 	if e != nil {
			// 		return nil, e
			// 	}
			// 	fmt.Println(a, b, c)
			// 	fieldCount++
			// 	continue // skip n/a
		} else if strings.HasPrefix(line, "| ") {
			if fieldCount >= headerCount {
				continue // skip empty or extra field
			}

			line = strings.TrimPrefix(line, "|")
			line = strings.TrimSpace(line)

			if strings.Contains(line, "{{n/a}}") {
				fieldCount++
				continue
			}

			if strings.Contains(line, "rowspan") {
				line = strings.Split(line, "|")[1]
				line = strings.TrimSpace(line)
			} else if strings.Contains(line, "colspan") {
				parts := strings.Split(line, "|")
				parts[0] = strings.TrimSpace(parts[0])
				colWidth := strings.TrimPrefix(parts[0], "colspan=\"")
				colWidth = strings.TrimSuffix(colWidth, "\"")
				inc, err := strconv.Atoi(colWidth)
				if err != nil {
					return nil, fmt.Errorf("failed to parse colspan: %s", err)
				}
				fieldCount += inc
			}

			switch index2Header[fieldCount] {
			case "Product Version":
				fallthrough
			case "Version":
				ipsw.Version = line
			case "Build":
				ipsw.Build = line
			case "Keys":
				parts := strings.Split(line, "<br/>")
				for _, part := range parts {
					part = strings.TrimSpace(part)
					part = strings.TrimPrefix(part, "[[")
					part = strings.TrimSuffix(part, "]]")
					part = strings.Split(part, "|")[1]
					ipsw.Devices = append(ipsw.Devices, part)
				}
			case "Baseband":
				ipsw.Baseband = line
			case "Release Date":
				ipsw.ReleaseDate = line
			case "OTA Download URL":
				fallthrough
			case "Download URL":
				line = strings.TrimPrefix(line, "[")
				line = strings.TrimSuffix(line, "]")
				ipsw.DownloadUrl = line
			case "SHA1 Hash":
				line = strings.TrimPrefix(line, "<code>")
				line = strings.TrimSuffix(line, "</code>")
				ipsw.Sha1Hash = line
			case "File Size":
				fs, err := strconv.Atoi(strings.Replace(line, ",", "", -1))
				if err != nil {
					// return nil, err
					fieldCount++
					continue
				}
				ipsw.FileSize = fs
			case "Release Notes":
				fallthrough
			case "Documentation":
				line = strings.TrimPrefix(line, "[")
				line = strings.TrimSuffix(line, "]")
				ipsw.Documentation = line
			}

			fieldCount++

			if fieldCount >= headerCount {
				if len(ipsw.DownloadUrl) > 0 {
					results = append(results, ipsw)
				}
				ipsw = &WikiIPSW{}
			}
		}
	}

	return results, nil
}

// GetWikiIPSWs queries theiphonewiki.com for IPSWs
func GetWikiIPSWs(proxy string, insecure bool) ([]*WikiIPSW, error) {
	var ipsws []*WikiIPSW

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           GetProxy(proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
	}

	req, err := http.NewRequest("GET", iPhoneWikiAPI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	q := req.URL.Query()
	q.Add("format", "json")
	q.Add("action", "parse")
	q.Add("page", "Firmware")
	q.Add("prop", "links")
	q.Add("redirects", "true")
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get response: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get response: %s", resp.Status)
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// parse the response
	var parseResp wikiParseResults
	if err := json.Unmarshal(data, &parseResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	for _, link := range parseResp.Parse.Links {
		if strings.HasPrefix(link.Link, "Firmware/") {
			// if strings.HasPrefix(link.Link, "Firmware/Apple Watch/") {

			wpage, err := getWikiPage(link.Link, proxy, insecure)
			if err != nil {
				return nil, fmt.Errorf("failed to parse page %s: %w", link.Link, err)
			}

			if utils.StrSliceContains(wpage.Parse.ExternalLinks, ".ipsw") {
				wtable, err := getWikiTable(link.Link, proxy, insecure)
				if err != nil {
					return nil, fmt.Errorf("failed to parse wikitable for %s: %w", link.Link, err)
				}
				// parse the wikitable
				tableIPSWs, err := parseWikiTable(wtable.Parse.WikiText.Text)
				if err != nil {
					return nil, fmt.Errorf("failed to parse wikitable: %w", err)
				}
				ipsws = append(ipsws, tableIPSWs...)
			}
		}
	}

	return ipsws, nil
}

func GetWikiOTAs(proxy string, insecure bool) ([]*WikiOTA, error) {
	var otas []*WikiOTA

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           GetProxy(proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
	}

	req, err := http.NewRequest("GET", iPhoneWikiAPI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	q := req.URL.Query()
	q.Add("format", "json")
	q.Add("action", "parse")
	q.Add("page", "OTA Updates")
	q.Add("prop", "links")
	q.Add("redirects", "true")
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get response: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get response: %s", resp.Status)
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// parse the response
	var parseResp wikiParseResults
	if err := json.Unmarshal(data, &parseResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	for _, link := range parseResp.Parse.Links {
		// if strings.HasPrefix(link.Link, "OTA Updates/") {
		if strings.HasPrefix(link.Link, "OTA Updates/iPhone/15") {

			wpage, err := getWikiPage(link.Link, proxy, insecure)
			if err != nil {
				return nil, fmt.Errorf("failed to parse page %s: %w", link.Link, err)
			}

			if utils.StrSliceContains(wpage.Parse.ExternalLinks, ".zip") {
				wtable, err := getWikiTable(link.Link, proxy, insecure)
				if err != nil {
					return nil, fmt.Errorf("failed to parse wikitable for %s: %w", link.Link, err)
				}
				// parse the wikitable
				tableIPSWs, err := parseWikiTable(wtable.Parse.WikiText.Text)
				if err != nil {
					return nil, fmt.Errorf("failed to parse wikitable: %w", err)
				}
				fmt.Println(tableIPSWs)
				// otas = append(otas, tableIPSWs...)
			}
		}
	}

	return otas, nil
}

func GetWikiFirmwareKeys(proxy string, insecure bool) ([]*WikiOTA, error) {
	var otas []*WikiOTA

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           GetProxy(proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
	}

	req, err := http.NewRequest("GET", iPhoneWikiAPI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	q := req.URL.Query()
	q.Add("format", "json")
	q.Add("action", "parse")
	q.Add("page", "OTA Updates")
	q.Add("prop", "links")
	q.Add("redirects", "true")
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get response: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get response: %s", resp.Status)
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// parse the response
	var parseResp wikiParseResults
	if err := json.Unmarshal(data, &parseResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	for _, link := range parseResp.Parse.Links {
		// if strings.HasPrefix(link.Link, "OTA Updates/") {
		if strings.HasPrefix(link.Link, "OTA Updates/iPhone/15") {

			wpage, err := getWikiPage(link.Link, proxy, insecure)
			if err != nil {
				return nil, fmt.Errorf("failed to parse page %s: %w", link.Link, err)
			}

			if utils.StrSliceContains(wpage.Parse.ExternalLinks, ".zip") {
				wtable, err := getWikiTable(link.Link, proxy, insecure)
				if err != nil {
					return nil, fmt.Errorf("failed to parse wikitable for %s: %w", link.Link, err)
				}
				// parse the wikitable
				tableIPSWs, err := parseWikiTable(wtable.Parse.WikiText.Text)
				if err != nil {
					return nil, fmt.Errorf("failed to parse wikitable: %w", err)
				}
				fmt.Println(tableIPSWs)
				// otas = append(otas, tableIPSWs...)
			}
		}
	}

	return otas, nil
}
