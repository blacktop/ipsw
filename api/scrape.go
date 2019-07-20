package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/apex/log"
	"github.com/pkg/errors"
)

const (
	iphoneWikiURL    = "https://www.theiphonewiki.com"
	firmwarePath     = "/wiki/Firmware"
	betaFirmwarePath = "/wiki/Beta_Firmware"
)

var (
	lastBaseBand []string
	columnCount  int
)

func processTr(tr *goquery.Selection, isHeader bool) (IPSW, error) {

	ipsw := IPSW{}
	tableElements := []*goquery.Selection{}

	// get table data
	tr.Find("td").Each(func(_ int, td *goquery.Selection) {
		tableElements = append(tableElements, td)
		if isHeader {
			columnCount++
		}
	})

	// skip header row
	if len(tableElements) == 0 {
		return IPSW{}, fmt.Errorf("this is the table header")
	}

	ipsw.Version = strings.TrimSpace(tableElements[0].Text())
	ipsw.BuildID = strings.TrimSpace(tableElements[1].Text())
	keys := []string{}
	tableElements[2].Find("a").Each(func(_ int, alink *goquery.Selection) {
		keys = append(keys, alink.Text())
	})
	// ipsw.Keys = keys

	if len(tableElements) == 8 {
		// ipsw.Baseband = append(ipsw.Baseband, strings.TrimSpace(tableElements[3].Text()))
		// ipsw.Baseband = append(ipsw.Baseband, strings.TrimSpace(tableElements[4].Text()))
		// lastBaseBand = ipsw.Baseband
		// ipsw.ReleaseDate = strings.TrimSpace(tableElements[5].Text())
		link, _ := tableElements[6].Find("a").Attr("href")
		ipsw.URL = link
		fileSize, err := strconv.Atoi(strings.Replace(strings.TrimSpace(tableElements[7].Text()), ",", "", -1))
		if err != nil {
			err = errors.Wrap(err, "unable to convert str to int")
		}
		ipsw.FileSize = fileSize
	}

	if len(tableElements) == 7 {
		// ipsw.Baseband = append(ipsw.Baseband, strings.TrimSpace(tableElements[3].Text()))
		// lastBaseBand = ipsw.Baseband
		// ipsw.ReleaseDate = strings.TrimSpace(tableElements[4].Text())
		link, _ := tableElements[5].Find("a").Attr("href")
		ipsw.URL = link
		fileSize, err := strconv.Atoi(strings.Replace(strings.TrimSpace(tableElements[6].Text()), ",", "", -1))
		if err != nil {
			err = errors.Wrap(err, "unable to convert str to int")
		}
		ipsw.FileSize = fileSize
	}

	if len(tableElements) == 6 {
		// ipsw.Baseband = lastBaseBand
		// ipsw.ReleaseDate = strings.TrimSpace(tableElements[3].Text())
		link, _ := tableElements[4].Find("a").Attr("href")
		ipsw.URL = link
		fileSize, err := strconv.Atoi(strings.Replace(strings.TrimSpace(tableElements[5].Text()), ",", "", -1))
		if err != nil {
			err = errors.Wrap(err, "unable to convert str to int")
		}
		ipsw.FileSize = fileSize
	}

	return ipsw, nil
}

func getFirmwareLinks(url string) []string {

	links := []string{}

	res, err := http.Get(url)
	if err != nil {
		log.Fatal(err.Error())
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		log.Fatalf("status code error: %d %s", res.StatusCode, res.Status)
	}

	// Load the HTML document
	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		log.Fatal(err.Error())
	}

	doc.Find("#mw-content-text > div a").Each(func(_ int, a *goquery.Selection) {
		href, _ := a.Attr("href")
		if strings.Contains(href, firmwarePath+"/") || strings.Contains(href, betaFirmwarePath+"/") {
			links = append(links, href)
		}
	})
	return links
}

// ScrapeIPhoneWiki scraps iPhoneWiki and extracts/filters download links
func ScrapeIPhoneWiki() error {

	links := []string{}

	ipsws := []IPSW{}

	firmwareLinks := getFirmwareLinks(iphoneWikiURL + firmwarePath)
	betaFirmwareLinks := getFirmwareLinks(iphoneWikiURL + betaFirmwarePath)

	links = append(links, firmwareLinks...)
	links = append(links, betaFirmwareLinks...)

	// Request the HTML page.
	for _, link := range links {
		devices := []string{}

		res, err := http.Get(iphoneWikiURL + link)
		if err != nil {
			log.Fatal(err.Error())
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			log.Fatalf("status code error: %d %s", res.StatusCode, res.Status)
		}

		// Load the HTML document
		doc, err := goquery.NewDocumentFromReader(res.Body)
		if err != nil {
			log.Fatal(err.Error())
		}

		// get device names
		doc.Find("span.mw-headline").Each(func(_ int, span *goquery.Selection) {
			devices = append(devices, span.Text())
		})

		// Find the review items
		doc.Find("table").Each(func(i int, table *goquery.Selection) {

			var isHeader = true
			columnCount = 0
			device := devices[i]

			table.Find("tr").Each(func(idx int, tr *goquery.Selection) {
				if idx > 0 {
					isHeader = false
				}

				i, err := processTr(tr, isHeader)
				i.Identifier = device
				if err != nil {
					log.WithError(err).Error("parsing table row failed")
				} else {
					ipsws = append(ipsws, i)
				}
			})
		})
	}

	ipswJSON, _ := json.Marshal(ipsws)
	return ioutil.WriteFile("database/ipsw.json", ipswJSON, 0644)
}
