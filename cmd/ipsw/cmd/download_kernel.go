// +build !windows,cgo

/*
Copyright © 2019 blacktop

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	downloadCmd.AddCommand(downloadKernelCmd)
}

// downloadKernelCmd represents the downloadKernel command
var downloadKernelCmd = &cobra.Command{
	Use:   "kernel",
	Short: "Download just the kernelcache",
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		proxy, _ := cmd.Flags().GetString("proxy")
		insecure, _ := cmd.Flags().GetBool("insecure")

		// filters
		doDownload, _ := cmd.Flags().GetStringSlice("white-list")
		doNotDownload, _ := cmd.Flags().GetStringSlice("black-list")
		version, _ := cmd.Flags().GetString("version")
		device, _ := cmd.Flags().GetString("device")
		build, _ := cmd.Flags().GetString("build")

		if len(version) > 0 && len(build) > 0 {
			log.Fatal("you cannot supply a --version AND a --build (they are mutually exclusive)")
		}

		if len(version) > 0 {
			ipsws, err := download.GetAllIPSW(version)
			if err != nil {
				return errors.Wrap(err, "failed to query ipsw.me api")
			}

			urls := []string{}
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

			for _, u := range urls {
				// get a handle to ipsw object
				i, err := LookupByURL(ipsws, u)
				if err != nil {
					return errors.Wrap(err, "failed to get ipsw from download url")
				}

				log.WithFields(log.Fields{
					"device":  i.Identifier,
					"build":   i.BuildID,
					"version": i.Version,
					"signed":  i.Signed,
				}).Info("Getting Kernelcache")

				zr, err := download.NewRemoteZipReader(u, &download.RemoteConfig{
					Proxy:    proxy,
					Insecure: insecure,
				})
				if err != nil {
					return errors.Wrap(err, "failed to download kernelcaches from remote ipsw")
				}

				err = kernelcache.RemoteParse(zr)
				if err != nil {
					return errors.Wrap(err, "failed to download kernelcaches from remote ipsw")
				}
			}

		} else if len(device) > 0 || len(build) > 0 {
			if len(device) > 0 && len(build) > 0 {
				i, err := download.GetIPSW(device, build)
				if err != nil {
					return errors.Wrap(err, "failed to query ipsw.me api")
				}

				log.WithFields(log.Fields{
					"device":  i.Identifier,
					"build":   i.BuildID,
					"version": i.Version,
					"signed":  i.Signed,
				}).Info("Getting Kernelcache")

				zr, err := download.NewRemoteZipReader(i.URL, &download.RemoteConfig{
					Proxy:    proxy,
					Insecure: insecure,
				})
				err = kernelcache.RemoteParse(zr)
				if err != nil {
					return errors.Wrap(err, "failed to download kernelcaches from remote ipsw")
				}
			}
		} else {
			log.Fatal("you must supply a --device AND a --build")
		}
		return nil
	},
}
