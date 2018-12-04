//go:generate statik -src=./database

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/AlecAivazis/survey"
	"github.com/apex/log"
	clihander "github.com/apex/log/handlers/cli"
	"github.com/blacktop/ipsw/api"
	"github.com/blacktop/ipsw/dyld"
	"github.com/blacktop/ipsw/kernelcache"
	_ "github.com/blacktop/ipsw/statik"
	"github.com/blacktop/ipsw/utils"
	"github.com/blacktop/partialzip"
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

func findKernelInList(list []string) string {
	for _, v := range list {
		if strings.Contains(v, "kernel") {
			return v
		}
	}
	return ""
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

	app.Name = "ipsw"
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
	}
	app.Commands = []cli.Command{
		// {
		// 	Name:  "generate",
		// 	Usage: "crawl theiphonewiki.com and create JSON database",
		// 	Action: func(c *cli.Context) error {
		// 		ScrapeIPhoneWiki()
		// 		return nil
		// 	},
		// },
		{
			Name:  "diff",
			Usage: "diff kernelcache (using assert strings)",
			Action: func(c *cli.Context) error {
				if c.GlobalBool("verbose") {
					log.SetLevel(log.DebugLevel)
				}
				if c.Args().Present() {
					if _, err := os.Stat(c.Args().First()); os.IsNotExist(err) {
						return fmt.Errorf("file %s does not exist", c.Args().First())
					}
					kernelcache.ParseMachO(c.Args().First())
				} else {
					log.Fatal("Please supply a kernelcache to diff from")
				}
				return nil
			},
		},
		{
			Name:  "extract",
			Usage: "extract and decompress a kernelcache",
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "dyld, d",
					Usage: "extract dyld_shared_cache",
				},
			},
			Action: func(c *cli.Context) error {
				if c.GlobalBool("verbose") {
					log.SetLevel(log.DebugLevel)
				}
				if c.Args().Present() {
					if _, err := os.Stat(c.Args().First()); os.IsNotExist(err) {
						return fmt.Errorf("file %s does not exist", c.Args().First())
					}
					if c.Bool("dyld") {
						if runtime.GOOS == "darwin" {
							log.Fatal("dyld_shared_cache extraction only works on macOS :(")
						}
						return dyld.Extract(c.Args().First())
					}
					kernelcache.Extract(c.Args().First())

				} else {
					log.Fatal("Please supply a IPSW to extract from")
				}
				return nil
			},
		},
		{
			Name:  "decompress",
			Usage: "decompress a kernelcache",
			Action: func(c *cli.Context) error {
				if c.GlobalBool("verbose") {
					log.SetLevel(log.DebugLevel)
				}
				if c.Args().Present() {
					if _, err := os.Stat(c.Args().First()); os.IsNotExist(err) {
						return fmt.Errorf("file %s does not exist", c.Args().First())
					}
					kernelcache.Decompress(c.Args().First())
				} else {
					log.Fatal("Please supply a kernelcache to decompress")
				}
				return nil
			},
		},
		{
			Name:  "download",
			Usage: "download and parse ipsw from the internet",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "proxy",
					Value:  "",
					Usage:  "HTTP/HTTPS proxy",
					EnvVar: "HTTPS_PROXY",
				},
				cli.BoolFlag{
					Name:  "insecure",
					Usage: "do not verify ssl certs",
				},
				cli.BoolFlag{
					Name:  "dec",
					Usage: "decompress kernelcache after downloading ipsw",
				},
				cli.BoolFlag{
					Name:  "kernel",
					Usage: "only download the kernelcache from ipsw",
				},
				cli.StringFlag{
					Name:   "device, d",
					Value:  "",
					Usage:  "iOS Device",
					EnvVar: "IOS_DEVICE",
				},
				cli.StringFlag{
					Name:   "iversion,iv",
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
			},
			Action: func(c *cli.Context) error {

				if c.GlobalBool("verbose") {
					log.SetLevel(log.DebugLevel)
				}

				if len(c.String("device")) > 0 {
					if len(c.String("build")) > 0 {
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
							err = DownloadFile(i.URL, c.String("proxy"), c.Bool("insecure"))
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
					}
				} else if len(c.String("iversion")) > 0 {
					urls := []string{}
					ipsws, err := api.GetAllIPSW(c.String("iversion"))
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
						Message: fmt.Sprintf("You are about to download %d ipsw files. Continue?", len(urls)),
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

								if c.Bool("kernel") {
									log.WithFields(log.Fields{
										"device":  i.Identifier,
										"build":   i.BuildID,
										"version": i.Version,
										"signed":  i.Signed,
									}).Info("Getting Kernelcache")
									pzip, err := partialzip.New(url)
									if err != nil {
										return errors.Wrap(err, "failed to create partialzip instance")
									}
									kpath := findKernelInList(pzip.List())
									if len(kpath) > 0 {
										_, err = pzip.Download(kpath)
										if err != nil {
											return errors.Wrap(err, "failed to download file")
										}
										kernelcache.Decompress(kpath)
										continue
									}
								} else {
									log.WithFields(log.Fields{
										"device":  i.Identifier,
										"build":   i.BuildID,
										"version": i.Version,
										"signed":  i.Signed,
									}).Info("Getting IPSW")
									// download file
									err = DownloadFile(url, c.String("proxy"), c.Bool("insecure"))
									if err != nil {
										return errors.Wrap(err, "failed to download file")
									}
									// verify download
									if ok, _ := utils.Verify(i.MD5, path.Base(url)); !ok {
										return fmt.Errorf("bad download: ipsw %s md5 hash is incorrect", path.Base(url))
									}
								}
							} else {
								log.Warnf("ipsw already exits: %s", path.Base(url))
							}

							if c.Bool("dec") {
								kernelcache.Extract(path.Base(url))
							}
						}
					}
				} else {
					cli.ShowAppHelp(c)
				}
				return nil
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err.Error())
	}
}
