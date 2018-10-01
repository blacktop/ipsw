//go:generate statik -src=./database

package main

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path"
	"runtime"
	"sync"
	"time"

	"github.com/apex/log"
	clihander "github.com/apex/log/handlers/cli"
	"github.com/blacktop/get-ipsws/api"
	"github.com/blacktop/get-ipsws/kernelcache"
	"github.com/blacktop/get-ipsws/lzss"
	_ "github.com/blacktop/get-ipsws/statik"
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
			Usage: "decompress the kernelcache",
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

		if len(c.String("device")) > 0 && len(c.String("build")) > 0 {
			// i := api.GetDevice("iPhone10,1")
			i, err := api.GetIPSW(c.String("device"), c.String("build"))
			if err != nil {
				return errors.Wrap(err, "failed to query ipsw.me api")
			}

			if _, err := os.Stat(path.Base(i.URL)); os.IsNotExist(err) {
				log.WithFields(log.Fields{
					"device": c.String("device"),
					"build":  c.String("build"),
				}).Info("Getting IPSW")
				err = DownloadFile(path.Base(i.URL), i.URL)
				if err != nil {
					return errors.Wrap(err, "failed to download file")
				}
			} else {
				log.Warnf("ipsw already exits: %s", path.Base(i.URL))
			}

			if c.Bool("dec") {
				log.Info("Extracting Kernelcache from IPSW")
				kcache, err := Unzip(path.Base(i.URL), "")
				if err != nil {
					return errors.Wrap(err, "failed extract kernelcache from ipsw")
				}
				kc, err := kernelcache.Open(kcache)
				if err != nil {
					return errors.Wrap(err, "failed parse compressed kernelcache")
				}
				log.Info("Decompressing Kernelcache")
				dec := lzss.Decompress(kc.Data)
				err = ioutil.WriteFile(kcache+".decompressed", dec[:kc.Header.UncompressedSize], 0644)
				if err != nil {
					return errors.Wrap(err, "failed to decompress kernelcache")
				}
			}

			// ipswList := QueryDB(c.String("build"))

			// for _, ipsw := range ipswList {
			// 	DownloadFile(ipsw.FileName, ipsw.DownloadURL)
			// }

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
