package download

import (
	"bufio"
	"container/list"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/sm"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
	semver "github.com/hashicorp/go-version"
)

const (
	iphoneWikiApiURL = "https://theapplewiki.com/api.php"
	ipswPage         = "Firmware"
	ipswKeysPage     = "Firmware Keys"
	ipswBetaPage     = "Beta Firmware"
	rsrPage          = "Rapid Security Responses"
	rsrBetaPage      = "Beta Rapid Security Responses"
	otaPage          = "OTA Updates"
	otaBetaPage      = "Beta OTA Updates"
	appleTV          = "Apple TV"
	appleWatch       = "Apple Watch"
	homePod          = "HomePod"
	macOS            = "Mac"
	macServer        = "Mac Server"
	ibridge          = "iBridge"
	ipad             = "iPad"
	ipadAir          = "iPad Air"
	ipadPro          = "iPad Pro"
	ipadMini         = "iPad mini"
	iphone           = "iPhone"
	ipodTouch        = "iPod Touch"
)

type Queue struct {
	l   *list.List
	len int
}

func NewQueue(len int) *Queue {
	return &Queue{
		l:   list.New(),
		len: len,
	}
}

func (q *Queue) Len() int {
	return q.l.Len()
}

func (q *Queue) IsEmpty() bool {
	return q.l.Len() == 0
}

func (q *Queue) Push(item string) {
	for q.l.Len() >= q.len {
		q.l.Remove(q.l.Front())
	}
	q.l.PushBack(item)
}

func (q *Queue) Peek() string {
	if q.IsEmpty() {
		return ""
	}
	return q.l.Back().Value.(string)
}

func (q *Queue) Pop() string {
	if q.IsEmpty() {
		return ""
	}
	return q.l.Remove(q.l.Back()).(string)
}

type WikiIPSW struct {
	Version       string    `json:"version,omitempty"`
	VersionExtra  string    `json:"version_extra,omitempty"`
	Build         string    `json:"build,omitempty"`
	Devices       []string  `json:"keys,omitempty"`
	Baseband      string    `json:"baseband,omitempty"`
	ReleaseDate   time.Time `json:"release_date,omitempty"`
	DownloadURL   string    `json:"download_url,omitempty"`
	Sha1Hash      string    `json:"sha1,omitempty"`
	FileSize      int       `json:"file_size,omitempty"`
	Documentation []string  `json:"doc,omitempty"`
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

	req, err := http.NewRequest("GET", iphoneWikiApiURL, nil)
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

	data, err := io.ReadAll(resp.Body)
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

	req, err := http.NewRequest("GET", iphoneWikiApiURL, nil)
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

	data, err := io.ReadAll(resp.Body)
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

func getRowOrColInc(line string) (rinc int, cinc int, field string, err error) {
	rowRE := regexp.MustCompile(`rowspan=\"(\s?)(?P<rinc>\d+)(\s?)\"`)
	if rowRE.MatchString(line) {
		matches := rowRE.FindStringSubmatch(line)
		if len(matches) != 4 {
			return 0, 0, "", fmt.Errorf("failed to parse rowspan")
		}
		rinc, err = strconv.Atoi(matches[2])
		if err != nil {
			return 0, 0, "", fmt.Errorf("failed to parse rowspan: %w", err)
		}
	}

	colRE := regexp.MustCompile(`colspan=\"(\s?)(?P<cinc>\d+)(\s?)\"`)
	if colRE.MatchString(line) {
		matches := colRE.FindStringSubmatch(line)
		if len(matches) != 4 {
			return 0, 0, "", fmt.Errorf("failed to parse colspan")
		}
		cinc, err = strconv.Atoi(matches[2])
		if err != nil {
			return 0, 0, "", fmt.Errorf("failed to parse colspan: %w", err)
		}
	}

	fieldRE := regexp.MustCompile(`((rowspan|colspan)=\"(\s?)(?P<test>\d+)(\s?)\"\s){1,2}(\|?\s?)(?P<field>.*)`)
	if fieldRE.MatchString(line) {
		matches := fieldRE.FindStringSubmatch(line)
		if len(matches) == 0 {
			return 0, 0, "", fmt.Errorf("failed to parse field")
		}
		field = strings.TrimSpace(matches[len(matches)-1])
	}

	return
}

func getVersionParts(input string) (version, extra string, err error) {
	re := regexp.MustCompile(`^(?P<num>(0|[1-9]\d*)((\.(0|[1-9]\d*))+)?)(?P<ext>.*)$`)
	if re.MatchString(input) {
		matches := re.FindStringSubmatch(input)
		if len(matches) == 0 {
			return "", "", fmt.Errorf("failed to parse version")
		}
		version = strings.TrimSpace(matches[1])
		extra = strings.TrimSpace(matches[len(matches)-1])
		ere := regexp.MustCompile(`\[\[(?P<detail>.*)\|(?P<simp>.*)\]\](?P<iter>.*)`)
		if ere.MatchString(input) {
			matches := ere.FindStringSubmatch(input)
			if len(matches) == 0 {
				return "", "", fmt.Errorf("failed to parse version extra")
			}
			// detail := strings.TrimSpace(matches[1])
			simp := strings.TrimSpace(matches[2])
			iter := strings.TrimSpace(matches[3])
			extra = fmt.Sprintf("%s%s", simp, iter)
		}
	}
	return
}

// parse wikitable
func parseWikiTable(text string) ([]WikiIPSW, error) {
	var results []WikiIPSW

	fieldCount := 0
	headerCount := 0
	ipsw := WikiIPSW{}
	index2Header := make(map[int]string)
	header2Values := make(map[string]*Queue)

	machine := sm.Machine{
		ID:      "mediawiki",
		Initial: "title",
		States: sm.StateMap{
			"title": sm.MachineState{
				On: sm.TransitionMap{
					"start": sm.MachineTransition{
						To: "start_table",
					},
				},
			},
			"start_table": sm.MachineState{
				On: sm.TransitionMap{
					"read_header": sm.MachineTransition{
						To: "header",
					},
				},
			},
			"header": sm.MachineState{
				On: sm.TransitionMap{
					"read_subheader": sm.MachineTransition{
						To: "subheader",
					},
				},
			},
			"subheader": sm.MachineState{
				On: sm.TransitionMap{
					"process_item": sm.MachineTransition{
						To: "process_item",
					},
				},
			},
			"process_item": sm.MachineState{
				On: sm.TransitionMap{
					// "item_done": sm.MachineTransition{
					// 	To: "item_done",
					// },
					"stop": sm.MachineTransition{
						To: "end_table",
					},
				},
			},
			// "item_done": sm.MachineState{
			// 	On: sm.TransitionMap{
			// 		"another": sm.MachineTransition{
			// 			To: "start_item",
			// 		},
			// 		"stop": sm.MachineTransition{
			// 			To: "end_table",
			// 		},
			// 	},
			// },
			"end_table": sm.MachineState{
				On: sm.TransitionMap{
					"done": sm.MachineTransition{
						To: "title",
					},
				},
			},
		},
	}

	parseItem := func(i int) error {
		switch v := index2Header[i]; v {
		case "Product Version", "Version":
			version := header2Values[v].Pop()
			num, extra, err := getVersionParts(version)
			if err == nil {
				ipsw.Version = num
				ipsw.VersionExtra = extra
			}
		case "Build":
			ipsw.Build = header2Values[v].Pop()
		case "Keys":
			keys := header2Values[v].Pop()
			if keys == "" {
				return nil
			}
			var parts []string
			if strings.Contains(keys, "<br/>") {
				parts = strings.Split(keys, "<br/>")
			} else {
				parts = strings.Split(keys, "<br />")
			}
			for _, part := range parts {
				part = strings.TrimSpace(part)
				part = strings.Trim(part, "[]")
				if _, dev, ok := strings.Cut(part, "|"); ok {
					ipsw.Devices = append(ipsw.Devices, dev)
				}
			}
		case "Baseband":
			ipsw.Baseband = header2Values[v].Pop()
		case "Release Date":
			// example: "{{date|2017|07|19}}"
			dstr := header2Values[v].Pop()
			if dstr != "Preinstalled" {
				dstr = strings.TrimPrefix(dstr, "{{date|")
				dstr = strings.TrimSuffix(dstr, "}}")
				date, error := time.Parse("2006|01|02", dstr)
				if error == nil {
					ipsw.ReleaseDate = date
				}
			}
		case "Download URL", "IPSW Download URL", "OTA Download URL":
			url := header2Values[v].Pop()
			url = strings.Trim(url, "[]")
			parts := strings.Split(url, " ")
			if len(parts) > 1 {
				url = parts[0]
			}
			ipsw.DownloadURL = url
		case "SHA1 Hash":
			sha := header2Values[v].Pop()
			sha = strings.TrimPrefix(sha, "<code>")
			sha = strings.TrimSuffix(sha, "</code>")
			ipsw.Sha1Hash = sha
		case "File Size":
			fstr := header2Values[v].Pop()
			fs, err := strconv.Atoi(strings.Replace(fstr, ",", "", -1))
			if err == nil {
				ipsw.FileSize = fs
			}
		case "Release Notes":
			fallthrough
		case "Documentation":
			doc := header2Values[v].Pop()
			if strings.Contains(doc, "<br") {
				doc = strings.ReplaceAll(doc, "]<br/>[", "\n")
				doc = strings.ReplaceAll(doc, "]<br />[", "\n")
				doc = strings.Trim(doc, "[]")
				parts := strings.Split(doc, "\n")
				ipsw.Documentation = append(ipsw.Documentation, parts...)
			} else {
				ipsw.Documentation = append(ipsw.Documentation, doc)
			}
		default:
			header2Values[v].Pop() // pop into the ether
		}
		return nil
	}

	scanner := bufio.NewScanner(strings.NewReader(text))

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "\"{{") { /* title */
			if machine.Current() != "title" {
				return nil, fmt.Errorf("title: invalid state '%s'", machine.Current())
			}
			// log.Debugf("title: %s", line)
			continue
		} else if strings.HasPrefix(line, "==") { /* subtitle */
			if machine.Current() != "title" {
				return nil, fmt.Errorf("title: invalid state '%s'", machine.Current())
			}
			title := strings.Trim(strings.TrimSpace(line), "=[] ")
			board, name, ok := strings.Cut(title, "|")
			if ok {
				title = name
			}
			// log.Info(title)
			_ = title // TODO: use title
			_ = board // TODO: use board
			continue
		} else if strings.HasPrefix(line, "{|") { /* table start */
			if machine.Current() != "title" {
				return nil, fmt.Errorf("table start: invalid state '%s'", machine.Current())
			}
			machine.Transition("start")
			fieldCount = 0
			headerCount = 0
			index2Header = make(map[int]string)
			header2Values = make(map[string]*Queue)
			continue
		} else if strings.HasPrefix(line, "|}") { /* table end */
			if machine.Current() != "process_item" {
				return nil, fmt.Errorf("table end: invalid state '%s'", machine.Current())
			}
			machine.Transition("stop")
			for i := 0; i < headerCount; i++ {
				parseItem(i)
			}
			results = append(results, ipsw)
			machine.Transition("done")
		} else if strings.HasPrefix(line, "|-") { /* table row delimiter */
			switch machine.Current() {
			case "start_table":
				machine.Transition("read_header")
			case "header":
				machine.Transition("read_subheader")
			case "subheader":
				machine.Transition("process_item")
			case "process_item":
				for i := 0; i < headerCount; i++ {
					parseItem(i)
				}
				results = append(results, ipsw)
				machine.Transition("item_done")
				ipsw = WikiIPSW{}
				fieldCount = 0
			}
			continue
		} else if strings.HasPrefix(line, "!") { /* header values */
			if machine.Current() != "header" && machine.Current() != "subheader" {
				return nil, fmt.Errorf("parsing header: invalid state '%s'", machine.Current())
			}
			if machine.Current() == "header" {
				line = strings.TrimPrefix(line, "! ")
				if strings.Contains(line, "rowspan") {
					_, _, field, err := getRowOrColInc(line)
					if err != nil {
						return nil, fmt.Errorf("failed to parse colspan|rowspan: %s", err)
					}
					index2Header[headerCount] = field
					header2Values[field] = NewQueue(20)
					headerCount++
				} else if strings.Contains(line, "colspan") {
					_, colInc, field, err := getRowOrColInc(line)
					if err != nil {
						return nil, fmt.Errorf("failed to parse colspan|rowspan: %s", err)
					}
					header2Values[field] = NewQueue(20)
					for i := 0; i < colInc; i++ {
						index2Header[headerCount] = field
						headerCount++
					}
				} else {
					index2Header[headerCount] = line
					header2Values[line] = NewQueue(20)
					headerCount++
				}
			} else if machine.Current() == "subheader" {
				// FIXME: this replaces the 2nd colspan header (which works) but it's really supports to be a sub-header value (and could be ignored?)
				line = strings.TrimPrefix(line, "! ")
				if strings.HasPrefix(line, "class=") {
					_, line, _ = strings.Cut(line, " | ")
					line = strings.TrimSpace(line)
				}
				var last string
				for i := 0; i < headerCount; i++ {
					if last == index2Header[i] {
						index2Header[i] = line
						header2Values[line] = NewQueue(20)
						break
					}
					last = index2Header[i]
				}
			}
		} else if strings.HasPrefix(line, "|") { /* field values */
			if machine.Current() == "subheader" {
				machine.Transition("process_item") // skip missing subheader
			}
			if machine.Current() != "process_item" {
				return nil, fmt.Errorf("parsing items: invalid state '%s'", machine.Current())
			}

			for fieldCount < len(index2Header)-1 && header2Values[index2Header[fieldCount]].Len() > 0 {
				fieldCount++
			}

			line = strings.TrimPrefix(line, "| ")
			line = strings.TrimSpace(line)
			if strings.Contains(line, "Nowrap") {
				line = strings.Replace(line, "Nowrap", "", -1)
			}

			if line == "{{n/a}}" { // empty field
				header2Values[index2Header[fieldCount]].Push("")
				continue
			}

			if strings.Contains(line, "colspan") || strings.Contains(line, "rowspan") {
				rowInc, colInc, field, err := getRowOrColInc(line)
				if err != nil {
					return nil, fmt.Errorf("failed to parse colspan|rowspan: %s", err)
				}
				if colInc > 0 && rowInc > 0 {
					for i := 0; i < colInc-1; i++ {
						for j := 0; j < rowInc; j++ {
							header2Values[index2Header[fieldCount+i]].Push(field)
						}
					}
				} else if colInc > 0 {
					for i := 0; i < colInc-1; i++ {
						header2Values[index2Header[fieldCount+i]].Push(field)
					}
				} else if rowInc > 0 {
					for i := 0; i < rowInc; i++ {
						header2Values[index2Header[fieldCount]].Push(field)
					}
				}
			} else {
				// log.Debugf("field: %s, value: %s", index2Header[fieldCount], line)
				header2Values[index2Header[fieldCount]].Push(line)
			}
		}
	}

	return results, nil
}

type WikiConfig struct {
	Device  string
	Version string
	Build   string
	IPSW    bool
	OTA     bool
	Beta    bool
}

func CreateWikiFilter(cfg *WikiConfig) string {
	var page string
	var device string
	var major string

	if cfg.IPSW {
		if cfg.Beta {
			page = ipswBetaPage
		} else {
			page = ipswPage
		}
	}

	if cfg.OTA {
		if cfg.Beta {
			page = otaBetaPage
		} else {
			page = otaPage
		}
	}

	db, err := info.GetIpswDB()
	if err != nil {
		log.Fatalf("failed to get ipsw db: %v", err)
	}

	dev, err := db.LookupDevice(cfg.Device)
	if err != nil {
		log.Fatalf("failed to lookup device '%s': %v", cfg.Device, err)
	}

	switch {
	case strings.HasPrefix(dev.Name, "iPhone"):
		device = iphone
	case strings.HasPrefix(dev.Name, "iPad"):
		device = ipad
	}

	if len(cfg.Version) > 0 {
		ver, err := semver.NewVersion(cfg.Version)
		if err != nil {
			log.Fatalf("failed to convert version '%s' into semver object", cfg.Version)
		}
		major = strconv.Itoa(ver.Segments()[0])
	}

	if len(major) > 0 {
		return fmt.Sprintf("%s/%s/%s.x", page, device, major)
	}

	return fmt.Sprintf("%s/%s", page, device)
}

// GetWikiIPSWs queries theiphonewiki.com for IPSWs
func GetWikiIPSWs(filter, proxy string, insecure bool) ([]WikiIPSW, error) {
	var ipsws []WikiIPSW

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           GetProxy(proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
	}

	req, err := http.NewRequest("GET", iphoneWikiApiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	q := req.URL.Query()
	q.Add("format", "json")
	q.Add("action", "parse")
	q.Add("page", ipswPage)
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

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// parse the response
	var parseResp wikiParseResults
	if err := json.Unmarshal(data, &parseResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	for _, link := range parseResp.Parse.Links {
		if strings.HasPrefix(link.Link, filter) {

			log.Info(link.Link)

			if strings.HasSuffix(link.Link, "iPod") { // skip weird info page
				continue
			}

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

	req, err := http.NewRequest("GET", iphoneWikiApiURL, nil)
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

	data, err := io.ReadAll(resp.Body)
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

	req, err := http.NewRequest("GET", iphoneWikiApiURL, nil)
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

	data, err := io.ReadAll(resp.Body)
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
