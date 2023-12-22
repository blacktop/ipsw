/*
Copyright © 2018-2024 blacktop

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
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/ota/types"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(updateDBCmd)
	updateDBCmd.Flags().StringP("urls", "u", "", "Path to file containing list of URLs to scan (one per line)")
	updateDBCmd.Flags().StringP("remote", "r", "", "Remote IPSW/OTA URL to parse")
	updateDBCmd.Flags().StringP("db", "d", "", "Path to ipsw device DB JSON")
}

// updateDBCmd represents the updatedb command
var updateDBCmd = &cobra.Command{
	Use:          "updatedb",
	Short:        "Update internal device database",
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	Hidden:       true,
	Run: func(cmd *cobra.Command, args []string) {
		var devices info.Devices

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		urlList, _ := cmd.Flags().GetString("urls")
		remoteURL, _ := cmd.Flags().GetString("remote")
		dbPath, _ := cmd.Flags().GetString("db")

		mut := "Creating"
		if _, err := os.Stat(dbPath); err == nil {
			f, err := os.Open(dbPath)
			if err != nil {
				log.WithError(err).Fatal("failed to open DB file")
			}
			defer f.Close()
			dat, err := io.ReadAll(f)
			if err != nil {
				log.WithError(err).Fatal("failed to read DB file")
			}
			if err := json.Unmarshal(dat, &devices); err != nil {
				log.WithError(err).Fatal("failed to unmarshal DB JSON file")
			}
			mut = "Updating"
		} else {
			devices = make(info.Devices)
		}

		if len(urlList) > 0 {
			uf, err := os.Open(urlList)
			if err != nil {
				log.WithError(err).Fatal("failed to open URL list file")
			}
			defer uf.Close()

			scanner := bufio.NewScanner(uf)

			for scanner.Scan() {
				url := scanner.Text()
				if err := scanner.Err(); err != nil {
					log.WithError(err).Fatal("failed to read line from URL list file")
				}

				zr, err := download.NewRemoteZipReader(url, &download.RemoteConfig{})
				if err != nil {
					log.Error("failed to create remote zip reader")
					continue
				}
				i, err := info.ParseZipFiles(zr.File)
				if err != nil {
					log.WithError(err).Fatal("failed to parse remote zip")
				}
				if err := i.GetDevices(&devices); err != nil {
					log.WithError(err).Fatal("failed to get devices")
				}
			}
		} else if len(remoteURL) > 0 {
			zr, err := download.NewRemoteZipReader(remoteURL, &download.RemoteConfig{})
			if err != nil {
				log.WithError(err).Fatal("failed to create remote zip reader")
			}
			i, err := info.ParseZipFiles(zr.File)
			if err != nil {
				log.WithError(err).Fatal("failed to parse remote zip")
			}
			if i.Plists.Type == "OTA" {
				foundMap := false
				for _, f := range zr.File {
					if regexp.MustCompile(`.*plist$`).MatchString(f.Name) {
						switch {
						case strings.Contains(f.Name, "device_map.plist"):
							foundMap = true
							dat := make([]byte, f.UncompressedSize64)
							rc, err := f.Open()
							if err != nil {
								log.WithError(err).Fatal("failed to open file within zip")
							}
							defer rc.Close()
							io.ReadFull(rc, dat)
							dmap, err := types.ParseDeviceMap(dat)
							if err != nil {
								log.WithError(err).Fatal("failed to parse device map")
							}
							if err := i.GetDevicesFromMap(dmap, &devices); err != nil {
								log.WithError(err).Fatal("failed to get devices")
							}
						}
					}
				}
				if !foundMap {
					if err := i.GetDevices(&devices); err != nil {
						log.WithError(err).Fatal("failed to get devices")
					}
				}
			} else {
				if err := i.GetDevices(&devices); err != nil {
					log.WithError(err).Fatal("failed to get devices")
				}
			}
		} else { // TODO: add default "latest" URL streams here to collect new devices
			itunes, err := download.NewMacOsXML()
			if err != nil {
				log.WithError(err).Fatal("failed to create itunes API")
			}
			for _, build := range itunes.GetBuilds() {
				zr, err := download.NewRemoteZipReader(build.URL, &download.RemoteConfig{})
				if err != nil {
					log.WithError(err).Fatal("failed to create remote zip reader")
				}
				i, err := info.ParseZipFiles(zr.File)
				if err != nil {
					// log.WithError(err).Fatal("failed to parse remote ipsw")
					continue
				}
				if err := i.GetDevices(&devices); err != nil {
					log.WithError(err).Fatal("failed to get devices")
				}
			}
		}

		// OUTPUT JSON
		dat, err := json.Marshal(devices)
		if err != nil {
			log.WithError(err).Fatal("failed to marshal JSON")
		}
		if len(dbPath) > 0 {
			log.Infof("%s %s", mut, dbPath)
			if err := os.WriteFile(dbPath, dat, 0660); err != nil {
				log.WithError(err).Fatalf("failed to write file %s", dbPath)
			}
		} else {
			fmt.Println(string(dat))
		}
	},
}
