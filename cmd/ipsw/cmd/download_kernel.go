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
	"os"
	"path"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/api"
	"github.com/blacktop/ipsw/kernelcache"
	"github.com/blacktop/ipsw/utils"
	"github.com/blacktop/partialzip"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	downloadCmd.AddCommand(downloadKernelCmd)
}

func findKernelInList(list []string) string {
	for _, v := range list {
		if strings.Contains(v, "kernel") {
			return v
		}
	}
	return ""
}

// downloadKernelCmd represents the downloadKernel command
var downloadKernelCmd = &cobra.Command{
	Use:   "kernel",
	Short: "Download just the kernelcache",
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		// TODO: add this back in
		// proxy, _ := cmd.Flags().GetString("proxy")
		// insecure, _ := cmd.Flags().GetBool("insecure")

		// filters
		version, _ := cmd.Flags().GetString("version")
		device, _ := cmd.Flags().GetString("device")
		build, _ := cmd.Flags().GetString("build")

		if len(version) > 0 && len(build) > 0 {
			log.Fatal("you cannot supply a --version AND a --build (they are mutually exclusive)")
		}

		if len(version) > 0 {
			ipsws, err := api.GetAllIPSW(version)
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
					urls = append(urls, i.URL)
				}
			}
			urls = utils.Unique(urls)

			log.Debug("URLS TO DOWNLOAD:")
			for _, u := range urls {
				utils.Indent(log.Debug)(u)
			}

			for _, url := range urls {
				if _, err := os.Stat(path.Base(url)); os.IsNotExist(err) {
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
				}
			}

		} else if len(device) > 0 || len(build) > 0 {
			if len(device) > 0 && len(build) > 0 {
				i, err := api.GetIPSW(device, build)
				if err != nil {
					return errors.Wrap(err, "failed to query ipsw.me api")
				}

				log.WithFields(log.Fields{
					"device":  i.Identifier,
					"build":   i.BuildID,
					"version": i.Version,
					"signed":  i.Signed,
				}).Info("Getting Kernelcache")
				pzip, err := partialzip.New(i.URL)
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
				}
			}
		} else {
			log.Fatal("you must supply a --device AND a --build")
		}
		return nil
	},
}
