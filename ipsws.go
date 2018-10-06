//go:generate statik -src=./database

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/AlecAivazis/survey"
	"github.com/apex/log"
	clihander "github.com/apex/log/handlers/cli"
	"github.com/blacktop/get-ipsws/api"
	"github.com/blacktop/get-ipsws/kernelcache"
	_ "github.com/blacktop/get-ipsws/statik"
	"github.com/blacktop/get-ipsws/utils"
	"github.com/pkg/errors"
	"github.com/rakyll/statik/fs"
	"github.com/urfave/cli"
)

const (
	iphoneWikiURL    = "https://www.theiphonewiki.com"
	firmwarePath     = "/wiki/Firmware"
	betaFirmwarePath = "/wiki/Beta_Firmware"
	ipswMeAPI        = "https://api.ipsw.me/v4"
)

var (
	ctx *log.Entry
	wg  sync.WaitGroup
	// AppVersion stores the plugin's version
	AppVersion string
	// AppBuildTime stores the plugin's build time
	AppBuildTime string
	lastBaseBand []string
	columnCount  int
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

// LookupByRUL searchs for a ipsw in an array by a download URL
func LookupByRUL(ipsws []api.IPSW, dlURL string) (api.IPSW, error) {
	for _, i := range ipsws {
		if strings.EqualFold(dlURL, i.URL) {
			return i, nil
		}
	}
	return api.IPSW{}, fmt.Errorf("unable to find %s in ipsws", dlURL)
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
Author:{{if .Author}}
  {{.Author}}{{if .Email}} - <{{.Email}}>{{end}}{{else}}
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
		cli.BoolFlag{
			Name:  "dec",
			Usage: "decompress kernelcache after downloading ipsw",
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
		// cli.StringFlag{
		// 	Name:   "keys, k",
		// 	Value:  "",
		// 	Usage:  "iOS Keys",
		// 	EnvVar: "IOS_KEYS",
		// },
	}
	app.Commands = []cli.Command{
		{
			Name:  "extract",
			Usage: "extract and decompress a kernelcache",
			Action: func(c *cli.Context) error {
				if c.GlobalBool("verbose") {
					log.SetLevel(log.DebugLevel)
				}
				if c.Args().Present() {
					if _, err := os.Stat(c.Args().First()); os.IsNotExist(err) {
						kernelcache.Extract(c.Args().First())
					} else {
						return errors.New("file %s does not exist")
					}
				} else {
					log.Fatal("Please supply a IPSW to extract from")
				}
				return nil
			},
		},
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
			if len(c.String("device")) > 0 {
				i, err := api.GetIPSW(c.String("device"), c.String("build"))
				if err != nil {
					return errors.Wrap(err, "failed to query ipsw.me api")
				}

				if _, err := os.Stat(path.Base(i.URL)); os.IsNotExist(err) {
					log.WithFields(log.Fields{
						"device":  i.Identifier,
						"build":   i.BuildID,
						"version": i.Version,
						"signed":  i.Signed,
					}).Info("Getting IPSW")
					err = DownloadFile(i.URL)
					if err != nil {
						return errors.Wrap(err, "failed to download file")
					}
					if ok, _ := utils.Verify(i.MD5, path.Base(i.URL)); !ok {
						return fmt.Errorf("bad download: ipsw %s md5 hash is incorrect", path.Base(i.URL))
					}
				} else {
					log.Warnf("ipsw already exits: %s", path.Base(i.URL))
				}

				if c.Bool("dec") {
					kernelcache.Extract(path.Base(i.URL))
				}
			} else {
				urls := []string{}
				ipsws, err := api.GetAllIPSW(c.String("build"))
				if err != nil {
					return errors.Wrap(err, "failed to query ipsw.me api")
				}
				for _, i := range ipsws {
					urls = append(urls, i.URL)
				}
				urls = utils.Unique(urls)

				log.Debug("URLS TO DOWNLOAD:")
				for _, u := range urls {
					utils.Indent(log.Debug)(u)
				}

				cont := false
				prompt := &survey.Confirm{
					Message: fmt.Sprintf("You are about to download %d ipsw files. Do you want to continue?", len(urls)),
				}
				survey.AskOne(prompt, &cont, nil)

				if cont {
					for _, url := range urls {
						if _, err := os.Stat(path.Base(url)); os.IsNotExist(err) {
							// get a handle to ipsw object
							i, err := LookupByRUL(ipsws, url)
							if err != nil {
								return errors.Wrap(err, "failed to get ipsw from download url")
							}
							log.WithFields(log.Fields{
								"device":  i.Identifier,
								"build":   i.BuildID,
								"version": i.Version,
								"signed":  i.Signed,
							}).Info("Getting IPSW")
							// download file
							err = DownloadFile(url)
							if err != nil {
								return errors.Wrap(err, "failed to download file")
							}
							// verify download
							if ok, _ := utils.Verify(i.MD5, path.Base(url)); !ok {
								return fmt.Errorf("bad download: ipsw %s md5 hash is incorrect", path.Base(url))
							}
						} else {
							log.Warnf("ipsw already exits: %s", path.Base(url))
						}

						if c.Bool("dec") {
							kernelcache.Extract(path.Base(url))
						}
					}
				}
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
