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
	"archive/zip"
	"crypto/tls"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/api"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ranger"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	downloadCmd.AddCommand(patternCmd)
}

// patternCmd represents the pattern command
var patternCmd = &cobra.Command{
	Use:   "pattern",
	Short: "Download files that contain pattern",
	Args:  cobra.MinimumNArgs(1),
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
				}).Infof("Getting files that contain: %s", args[0])
				url, err := url.Parse(u)
				if err != nil {
					return errors.Wrap(err, "failed to parse url")
				}
				reader, err := ranger.NewReader(&ranger.HTTPRanger{
					URL: url,
					Client: &http.Client{
						Transport: &http.Transport{
							Proxy:           getProxy(proxy),
							TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
						},
					},
				})
				if err != nil {
					return errors.Wrap(err, "failed to create ranger reader")
				}
				length, err := reader.Length()
				if err != nil {
					return errors.Wrap(err, "failed to get reader length")
				}
				zr, err := zip.NewReader(reader, length)
				if err != nil {
					return errors.Wrap(err, "failed to create zip reader from ranger reader")
				}

				ifo, err := info.RemoteParse(u)
				if err != nil {
					return errors.Wrap(err, "failed to parse ipsw info")
				}

				for _, f := range zr.File {
					if strings.Contains(f.Name, args[0]) {
						folder := ifo.GetFolderForFile(path.Base(f.Name))
						os.Mkdir(folder, os.ModePerm)
						if _, err := os.Stat(filepath.Join(folder, filepath.Base(f.Name))); os.IsNotExist(err) {
							data := make([]byte, f.UncompressedSize64)
							rc, _ := f.Open()
							io.ReadFull(rc, data)
							rc.Close()

							err = ioutil.WriteFile(filepath.Join(folder, filepath.Base(f.Name)), data, 0644)
							if err != nil {
								return errors.Wrapf(err, "failed to write %s", f.Name)
							}
						} else {
							log.Warnf("%s already exists", filepath.Join(folder, filepath.Base(f.Name)))
						}
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
				}).Infof("Getting files that contain: %s", args[0])
				url, err := url.Parse(i.URL)
				if err != nil {
					return errors.Wrap(err, "failed to parse url")
				}
				reader, err := ranger.NewReader(&ranger.HTTPRanger{
					URL: url,
					Client: &http.Client{
						Transport: &http.Transport{
							Proxy:           getProxy(proxy),
							TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
						},
					},
				})
				if err != nil {
					return errors.Wrap(err, "failed to create ranger reader")
				}
				length, err := reader.Length()
				if err != nil {
					return errors.Wrap(err, "failed to get reader length")
				}
				zr, err := zip.NewReader(reader, length)
				if err != nil {
					return errors.Wrap(err, "failed to create zip reader from ranger reader")
				}
				ifo, err := info.RemoteParse(i.URL)
				if err != nil {
					return errors.Wrap(err, "failed to parse ipsw info")
				}
				for _, f := range zr.File {
					folder := ifo.GetFolderForFile(path.Base(f.Name))
					os.Mkdir(folder, os.ModePerm)
					if _, err := os.Stat(filepath.Join(folder, filepath.Base(f.Name))); os.IsNotExist(err) {
						data := make([]byte, f.UncompressedSize64)
						rc, _ := f.Open()
						io.ReadFull(rc, data)
						rc.Close()

						err = ioutil.WriteFile(filepath.Join(folder, filepath.Base(f.Name)), data, 0644)
						if err != nil {
							return errors.Wrapf(err, "failed to write %s", f.Name)
						}
					} else {
						log.Warnf("%s already exists", filepath.Join(folder, filepath.Base(f.Name)))
					}
				}
			}
		} else {
			log.Fatal("you must supply a --device AND a --build")
		}
		return nil
	},
}
