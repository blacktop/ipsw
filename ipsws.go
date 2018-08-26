//go:generate statik -src=./database

package main

import (
	"encoding/json"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/apex/log"
	clihander "github.com/apex/log/handlers/cli"
	_ "github.com/blacktop/get-ipsws/statik"
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

func getFmtStr() string {
	if runtime.GOOS == "windows" {
		return "%s"
	}
	return "\033[1m%s\033[0m"
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
