package cmd

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/api"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(downloadCmd)

	// Persistent Flags which will work for this command and all subcommands
	downloadCmd.PersistentFlags().String("proxy", "", "HTTP/HTTPS proxy")
	downloadCmd.PersistentFlags().Bool("insecure", false, "do not verify ssl certs")
	// Filters
	downloadCmd.PersistentFlags().StringArrayP("black-list", "", []string{viper.GetString("IPSW_DEVICE_BLACKLIST")}, "iOS device black list")
	downloadCmd.PersistentFlags().StringArrayP("white-list", "", []string{viper.GetString("IPSW_DEVICE_WHITELIST")}, "iOS device white list")
	downloadCmd.PersistentFlags().BoolP("yes", "y", false, "do not prompt user")
	downloadCmd.PersistentFlags().StringP("version", "v", viper.GetString("IPSW_VERSION"), "iOS Version (i.e. 12.3.1)")
	downloadCmd.PersistentFlags().StringP("device", "d", viper.GetString("IPSW_DEVICE"), "iOS Device (i.e. iPhone11,2)")
	downloadCmd.PersistentFlags().StringP("build", "b", viper.GetString("IPSW_BUILD"), "iOS BuildID (i.e. 16F203)")
}

func getProxy(proxy string) func(*http.Request) (*url.URL, error) {
	if len(proxy) > 0 {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			log.WithError(err).Error("bad proxy url")
		}
		return http.ProxyURL(proxyURL)
	}
	return http.ProxyFromEnvironment
}

// LookupByURL searchs for a ipsw in an array by a download URL
func LookupByURL(ipsws []download.IPSW, dlURL string) (download.IPSW, error) {
	for _, i := range ipsws {
		if strings.EqualFold(dlURL, i.URL) {
			return i, nil
		}
	}
	return download.IPSW{}, fmt.Errorf("unable to find %s in ipsws", dlURL)
}

// downloadCmd represents the download command
var downloadCmd = &cobra.Command{
	Use:   "download",
	Short: "Download and parse IPSW(s) from the internets",
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		proxy, _ := cmd.Flags().GetString("proxy")
		insecure, _ := cmd.Flags().GetBool("insecure")
		skip, _ := cmd.Flags().GetBool("yes")

		// filters
		version, _ := cmd.Flags().GetString("version")
		device, _ := cmd.Flags().GetString("device")
		doDownload, _ := cmd.Flags().GetStringArray("white-list")
		doNotDownload, _ := cmd.Flags().GetStringArray("black-list")
		build, _ := cmd.Flags().GetString("build")

		if len(version) > 0 && len(build) > 0 {
			log.Fatal("you cannot supply a --version AND a --build (they are mutually exclusive)")
		}

		if len(version) > 0 {
			urls := []string{}
			ipsws, err := download.GetAllIPSW(version)
			if err != nil {
				return errors.Wrap(err, "failed to query ipsw.me api")
			}
			for _, i := range ipsws {
				if len(device) > 0 {
					if strings.EqualFold(device, i.Identifier) {
						urls = append(urls, i.URL)
					}
				} else {
					if len(doDownload) > 0 {
						if utils.StrSliceContains(doDownload, i.Identifier) {
							urls = append(urls, i.URL)
						}
					} else if len(doNotDownload) > 0 {
						if !utils.StrSliceContains(doNotDownload, i.Identifier) {
							urls = append(urls, i.URL)
						}
					} else {
						urls = append(urls, i.URL)
					}
				}
			}
			urls = utils.Unique(urls)

			log.Debug("URLs to Download:")
			for _, u := range urls {
				utils.Indent(log.Debug, 2)(u)
			}

			// check canijailbreak.com
			jbs, _ := download.GetJailbreaks()
			if iCan, index, err := jbs.CanIBreak(version); err != nil {
				log.Error(err.Error())
			} else {
				if iCan {
					log.WithField("url", jbs.Jailbreaks[index].URL).Warnf("Yo, this shiz is jail breakable via %s B!!!!", jbs.Jailbreaks[index].Name)
					utils.Indent(log.Warn, 2)(jbs.Jailbreaks[index].Caveats)
				} else {
					log.Warnf("Yo, ain't no one jailbreaking this shizz NOT even %s my dude!!!!", download.GetRandomResearcher())
				}
			}

			cont := true
			if !skip {
				// if filtered to a single device skip the prompt
				if len(device) == 0 {
					cont = false
					prompt := &survey.Confirm{
						Message: fmt.Sprintf("You are about to download %d ipsw files. Continue?", len(urls)),
					}
					survey.AskOne(prompt, &cont)
				}
			}
			if cont {
				downloader := download.NewDownload(proxy, insecure)
				for _, url := range urls {
					destName := strings.Replace(path.Base(url), ",", "_", -1)
					if _, err := os.Stat(destName); os.IsNotExist(err) {
						// get a handle to ipsw object
						i, err := LookupByURL(ipsws, url)
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
						downloader.URL = url
						downloader.Sha1 = i.SHA1
						err = downloader.Do()
						if err != nil {
							return errors.Wrap(err, "failed to download file")
						}
						// append sha1 and filename to checksums file
						f, err := os.OpenFile("checksums.txt.sha1", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
						if err != nil {
							return errors.Wrap(err, "failed to open checksums.txt.sha1")
						}
						defer f.Close()
						if _, err = f.WriteString(i.SHA1 + "  " + destName + "\n"); err != nil {
							return errors.Wrap(err, "failed to write to checksums.txt.sha1")
						}
					} else {
						log.Warnf("ipsw already exists: %s", destName)
					}
				}
			}

		} else if len(device) > 0 || len(build) > 0 {
			if len(device) > 0 && len(build) > 0 {
				i, err := download.GetIPSW(device, build)
				if err != nil {
					return errors.Wrap(err, "failed to query ipsw.me api")
				}
				destName := strings.Replace(path.Base(i.URL), ",", "_", -1)
				if _, err := os.Stat(destName); os.IsNotExist(err) {
					log.WithFields(log.Fields{
						"device":  i.Identifier,
						"build":   i.BuildID,
						"version": i.Version,
						"signed":  i.Signed,
					}).Info("Getting IPSW")
					downloader := download.NewDownload(proxy, insecure)
					downloader.URL = i.URL
					downloader.Sha1 = i.SHA1
					err = downloader.Do()
					if err != nil {
						return errors.Wrap(err, "failed to download file")
					}
					// append sha1 and filename to checksums file
					f, err := os.OpenFile("checksums.txt.sha1", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
					if err != nil {
						return errors.Wrap(err, "failed to open checksums.txt.sha1")
					}
					defer f.Close()
					if _, err = f.WriteString(i.SHA1 + "  " + destName + "\n"); err != nil {
						return errors.Wrap(err, "failed to write to checksums.txt.sha1")
					}
				} else {
					log.Warnf("ipsw already exists: %s", destName)
				}
			}
		} else {
			log.Fatal("you must also supply a --device AND a --build")
		}
		return nil
	},
}
