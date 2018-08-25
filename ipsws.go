//go:generate statik -src=./database

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/apex/log"
	clihander "github.com/apex/log/handlers/cli"
	_ "github.com/blacktop/get-ipsws/statik"
	"github.com/dustin/go-humanize"
	"github.com/pkg/errors"
	"github.com/rakyll/statik/fs"
	"github.com/urfave/cli"
)

const (
	iphoneWikiURL    = "https://www.theiphonewiki.com"
	firmwarePath     = "/wiki/Firmware"
	betaFirmwarePath = "/wiki/Beta_Firmware"
)

var (
	ctx *log.Entry
	wg  sync.WaitGroup
	// AppVersion stores the plugin's version
	AppVersion string
	// AppBuildTime stores the plugin's build time
	AppBuildTime string
	lastBaseBand []string
)

// IPSW ipsw file
type IPSW struct {
	Device      string
	Version     string
	Build       string
	Keys        []string
	Baseband    []string
	ReleaseDate string
	DownloadURL string
	FileName    string
	FileSize    int
}

func init() {
	log.SetHandler(clihander.Default)
}

func getFmtStr() string {
	if runtime.GOOS == "windows" {
		return "%s"
	}
	return "\033[1m%s\033[0m"
}

// WriteCounter counts the number of bytes written to it. It implements to the io.Writer
// interface and we can pass this into io.TeeReader() which will report progress on each
// write cycle.
type WriteCounter struct {
	Total uint64
}

func (wc *WriteCounter) Write(p []byte) (int, error) {
	n := len(p)
	wc.Total += uint64(n)
	wc.PrintProgress()
	return n, nil
}

// PrintProgress prints download progress
func (wc WriteCounter) PrintProgress() {
	// Clear the line by using a character return to go back to the start and remove
	// the remaining characters by filling it with spaces
	fmt.Printf("\r%s", strings.Repeat(" ", 35))

	// Return again and print current status of download
	// We use the humanize package to print the bytes in a meaningful way (e.g. 10 MB)
	fmt.Printf("\rDownloading... %s complete", humanize.Bytes(wc.Total))
}

// DownloadFile will download a url to a local file. It's efficient because it will
// write as it downloads and not load the whole file into memory. We pass an io.TeeReader
// into Copy() to report progress on the download.
func DownloadFile(filepath string, url string) error {

	// Create the file, but give it a tmp file extension, this means we won't overwrite a
	// file until it's downloaded, but we'll remove the tmp extension once downloaded.
	out, err := os.Create(filepath + ".tmp")
	if err != nil {
		return err
	}
	defer out.Close()

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Create our progress reporter and pass it to be used alongside our writer
	counter := &WriteCounter{}
	_, err = io.Copy(out, io.TeeReader(resp.Body, counter))
	if err != nil {
		return err
	}

	// The progress use the same line so print a new line once it's finished downloading
	fmt.Print("\n")

	err = os.Rename(filepath+".tmp", filepath)
	if err != nil {
		return err
	}

	return nil
}

func multiDownload() error {
	// 	res, _ := http.Head("http://localhost/rand.txt") // 187 MB file of random numbers per line
	// 	maps := res.Header
	// 	length, _ := strconv.Atoi(maps["Content-Length"][0]) // Get the content length from the header request
	// 	limit := 10                                          // 10 Go-routines for the process so each downloads 18.7MB
	// 	len_sub := length / limit                            // Bytes for each Go-routine
	// 	diff := length % limit                               // Get the remaining for the last request
	// 	body := make([]string, 11)                           // Make up a temporary array to hold the data to be written to the file
	// 	for i := 0; i < limit; i++ {
	// 		wg.Add(1)

	// 		min := len_sub * i       // Min range
	// 		max := len_sub * (i + 1) // Max range

	// 		if i == limit-1 {
	// 			max += diff // Add the remaining bytes in the last request
	// 		}

	// 		go func(min int, max int, i int) {
	// 			client := &http.Client{}
	// 			req, _ := http.NewRequest("GET", "http://localhost/rand.txt", nil)
	// 			range_header := "bytes=" + strconv.Itoa(min) + "-" + strconv.Itoa(max-1) // Add the data for the Range header of the form "bytes=0-100"
	// 			req.Header.Add("Range", range_header)
	// 			resp, _ := client.Do(req)
	// 			defer resp.Body.Close()
	// 			reader, _ := ioutil.ReadAll(resp.Body)
	// 			body[i] = string(reader)
	// 			ioutil.WriteFile(strconv.Itoa(i), []byte(string(body[i])), 0x777) // Write to the file i as a byte array
	// 			wg.Done()
	// 			//          ioutil.WriteFile("new_oct.png", []byte(string(body)), 0x777)
	// 		}(min, max, i)
	// 	}
	// 	wg.Wait()
	return nil
}

func processTr(tr *goquery.Selection) (IPSW, error) {

	ipsw := IPSW{}
	tableElements := []*goquery.Selection{}

	// get table data
	tr.Find("td").Each(func(_ int, td *goquery.Selection) {
		tableElements = append(tableElements, td)
	})

	// skip header row
	if len(tableElements) == 0 {
		return IPSW{}, fmt.Errorf("this is the table header")
	}

	if len(tableElements) == 8 {
		ipsw.Version = strings.TrimSpace(tableElements[0].Text())
		ipsw.Build = strings.TrimSpace(tableElements[1].Text())
		keys := []string{}
		tableElements[2].Find("a").Each(func(_ int, alink *goquery.Selection) {
			keys = append(keys, alink.Text())
		})
		ipsw.Keys = keys
		// ipsw.Baseband = append(ipsw.Baseband, strings.TrimSpace(tableElements[3].Text()))
		// ipsw.Baseband = append(ipsw.Baseband, strings.TrimSpace(tableElements[4].Text()))
		// lastBaseBand = ipsw.Baseband
		ipsw.ReleaseDate = strings.TrimSpace(tableElements[5].Text())
		link, _ := tableElements[6].Find("a").Attr("href")
		ipsw.DownloadURL = link
		fileSize, err := strconv.Atoi(strings.Replace(strings.TrimSpace(tableElements[7].Text()), ",", "", -1))
		if err != nil {
			err = errors.Wrap(err, "unable to convert str to int")
		}
		ipsw.FileSize = fileSize
	}

	if len(tableElements) == 7 {
		ipsw.Version = strings.TrimSpace(tableElements[0].Text())
		ipsw.Build = strings.TrimSpace(tableElements[1].Text())
		keys := []string{}
		tableElements[2].Find("a").Each(func(_ int, alink *goquery.Selection) {
			keys = append(keys, alink.Text())
		})
		ipsw.Keys = keys
		// ipsw.Baseband = append(ipsw.Baseband, strings.TrimSpace(tableElements[3].Text()))
		// lastBaseBand = ipsw.Baseband
		ipsw.ReleaseDate = strings.TrimSpace(tableElements[4].Text())
		link, _ := tableElements[5].Find("a").Attr("href")
		ipsw.DownloadURL = link
		fileSize, err := strconv.Atoi(strings.Replace(strings.TrimSpace(tableElements[6].Text()), ",", "", -1))
		if err != nil {
			err = errors.Wrap(err, "unable to convert str to int")
		}
		ipsw.FileSize = fileSize
	}

	if len(tableElements) == 6 {
		ipsw.Version = strings.TrimSpace(tableElements[0].Text())
		ipsw.Build = strings.TrimSpace(tableElements[1].Text())
		keys := []string{}
		tableElements[2].Find("a").Each(func(_ int, alink *goquery.Selection) {
			keys = append(keys, alink.Text())
		})
		ipsw.Keys = keys
		// ipsw.Baseband = lastBaseBand
		ipsw.ReleaseDate = strings.TrimSpace(tableElements[3].Text())
		link, _ := tableElements[4].Find("a").Attr("href")
		ipsw.DownloadURL = link
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

		// Find the review items
		// doc.Find("#mw-content-text > div a").Each(func(i int, s *goquery.Selection) {
		doc.Find("table").Each(func(_ int, table *goquery.Selection) {

			table.Find("tr").Each(func(_ int, tr *goquery.Selection) {
				i, err := processTr(tr)
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

// QueryDB queries the IPSW json database
func QueryDB(build string) []IPSW {

	var jsonData []byte
	var ipsws []IPSW

	statikDB, err := fs.New()
	if err != nil {
		log.Fatal(err.Error())
	}

	jsonFile, err := statikDB.Open("/ipsw.json")
	if err != nil {
		log.Fatal(err.Error())
	}

	_, err = jsonFile.Read(jsonData)
	if err != nil {
		log.Fatal(err.Error())
	}

	if err := json.Unmarshal(jsonData, &ipsws); err != nil {
		panic(err)
	}

	return ipsws
}

var appHelpTemplate = `Usage: {{.Name}} {{if .Flags}}[OPTIONS] {{end}}COMMAND [arg...]
{{.Usage}}
Version: {{.Version}}{{if or .Author .Email}}
Author:{{if .Author}} {{.Author}}{{if .Email}} - <{{.Email}}>{{end}}{{else}}
  {{.Email}}{{end}}{{end}}
{{if .Flags}}
Options:
  {{range .Flags}}{{.}}
  {{end}}{{end}}
Commands:
  {{range .Commands}}{{.Name}}{{with .ShortName}}, {{.}}{{end}}{{ "\t" }}{{.Usage}}
  {{end}}
Run '{{.Name}} COMMAND --help' for more information on a command.
`

func main() {

	cli.AppHelpTemplate = appHelpTemplate
	app := cli.NewApp()

	app.Name = "get-ipsws"
	app.Author = "blacktop"
	app.Email = "https://github.com/blacktop"
	app.Version = AppVersion + ", BuildTime: " + AppBuildTime
	app.Compiled, _ = time.Parse("20060102", AppBuildTime)
	app.Usage = "IPSW Downloader"
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "verbose, V",
			Usage: "verbose output",
		},
		cli.StringFlag{
			Name:   "device, d",
			Value:  "",
			Usage:  "iOS Device",
			EnvVar: "IOS_DEVICE",
		},
		cli.StringFlag{
			Name:   "ios-version,iv",
			Value:  "",
			Usage:  "iOS Version",
			EnvVar: "IOS_VERSION",
		},
		cli.StringFlag{
			Name:   "build, b",
			Value:  "",
			Usage:  "iOS Build",
			EnvVar: "IOS_BUILD",
		},
		cli.StringFlag{
			Name:   "keys, k",
			Value:  "",
			Usage:  "iOS Keys",
			EnvVar: "IOS_KEYS",
		},
	}
	app.Commands = []cli.Command{
		{
			Name:  "generate",
			Usage: "crawl theiphonewiki.com and create JSON database",
			Action: func(c *cli.Context) error {
				ScrapeIPhoneWiki()
				return nil
			},
		},
	}
	app.Action = func(c *cli.Context) error {

		if c.Bool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		if len(c.String("build")) > 0 {

			ipswList := QueryDB(c.String("build"))

			for _, ipsw := range ipswList {
				DownloadFile(ipsw.FileName, ipsw.DownloadURL)
			}

		} else {
			cli.ShowAppHelp(c)
		}
		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err.Error())
	}
}
