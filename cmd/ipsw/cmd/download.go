package cmd

import (
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
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
	downloadCmd.PersistentFlags().BoolP("skip-all", "s", false, "Always skip resumable IPSWs")
	downloadCmd.PersistentFlags().BoolP("remove-commas", "_", false, "replace commas in IPSW filename with underscores")
	downloadCmd.PersistentFlags().StringP("version", "v", viper.GetString("IPSW_VERSION"), "iOS Version (i.e. 12.3.1)")
	downloadCmd.PersistentFlags().StringP("device", "d", viper.GetString("IPSW_DEVICE"), "iOS Device (i.e. iPhone11,2)")
	downloadCmd.PersistentFlags().StringP("build", "b", viper.GetString("IPSW_BUILD"), "iOS BuildID (i.e. 16F203)")
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

func checkCanIJailbreak(version string) {
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
}

func filterIPSWs(cmd *cobra.Command) ([]download.IPSW, error) {

	var err error
	var ipsws []download.IPSW
	var filteredIPSWs []download.IPSW

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
		ipsws, err = download.GetAllIPSW(version)
		if err != nil {
			return nil, errors.Wrap(err, "failed to query ipsw.me api")
		}
	} else if len(build) > 0 {
		version, err = download.GetVersion(build)
		if err != nil {
			return nil, errors.Wrap(err, "failed to query ipsw.me api")
		}
		ipsws, err = download.GetAllIPSW(version)
		if err != nil {
			return nil, errors.Wrap(err, "failed to query ipsw.me api")
		}
	} else {
		return nil, fmt.Errorf("you must also supply a --version OR a --build (or use download latest)")
	}

	for _, i := range ipsws {
		if len(device) > 0 {
			if strings.EqualFold(device, i.Identifier) {
				filteredIPSWs = append(filteredIPSWs, i)
			}
		} else {
			if len(doDownload) > 0 {
				if utils.StrSliceContains(doDownload, i.Identifier) {
					filteredIPSWs = append(filteredIPSWs, i)
				}
			} else if len(doNotDownload) > 0 {
				if !utils.StrSliceContains(doNotDownload, i.Identifier) {
					filteredIPSWs = append(filteredIPSWs, i)
				}
			} else {
				filteredIPSWs = append(filteredIPSWs, i)
			}
		}
	}

	unique := make(map[string]bool, len(filteredIPSWs))
	uniqueIPSWs := make([]download.IPSW, len(unique))
	for _, i := range filteredIPSWs {
		if len(i.URL) != 0 {
			if !unique[i.URL] {
				uniqueIPSWs = append(uniqueIPSWs, i)
				unique[i.URL] = true
			}
		}
	}

	if len(uniqueIPSWs) == 0 {
		return nil, fmt.Errorf("filter flags matched 0 IPSWs")
	}

	return uniqueIPSWs, nil
}

func getDestName(url string, removeCommas bool) string {
	var destName string
	if removeCommas {
		destName = strings.Replace(path.Base(url), ",", "_", -1)
	} else {
		destName = path.Base(url)
	}
	return destName
}

// downloadCmd represents the download command
var downloadCmd = &cobra.Command{
	Use:   "download [options]",
	Short: "Download and parse IPSW(s) from the internets",
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		proxy, _ := cmd.Flags().GetString("proxy")
		insecure, _ := cmd.Flags().GetBool("insecure")
		confirm, _ := cmd.Flags().GetBool("yes")
		skipAll, _ := cmd.Flags().GetBool("skip-all")
		removeCommas, _ := cmd.Flags().GetBool("remove-commas")

		ipsws, err := filterIPSWs(cmd)
		if err != nil {
			log.Fatal(err.Error())
		}

		log.Debug("URLs to Download:")
		for _, i := range ipsws {
			utils.Indent(log.Debug, 2)(i.URL)
		}

		cont := true
		if !confirm {
			// if filtered to a single device skip the prompt
			if len(ipsws) > 1 {
				cont = false
				prompt := &survey.Confirm{
					Message: fmt.Sprintf("You are about to download %d ipsw files. Continue?", len(ipsws)),
				}
				survey.AskOne(prompt, &cont)
			}
		}

		if cont {
			for _, i := range ipsws {
				destName := getDestName(i.URL, removeCommas)
				if _, err := os.Stat(destName); os.IsNotExist(err) {
					log.WithFields(log.Fields{
						"device":  i.Identifier,
						"build":   i.BuildID,
						"version": i.Version,
						"signed":  i.Signed,
					}).Info("Getting IPSW")

					downloader := download.NewDownload(proxy, insecure, skipAll, Verbose)
					downloader.URL = i.URL
					downloader.Sha1 = i.SHA1
					downloader.DestName = destName

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
		return nil
	},
}
