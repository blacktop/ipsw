/*
Copyright © 2022 blacktop

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
	"io/ioutil"
	"os"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/pkg/info"
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
			dat, err := ioutil.ReadAll(f)
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
					// log.WithError(err).Fatal("failed to create remote zip reader")
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
			if err := i.GetDevices(&devices); err != nil {
				log.WithError(err).Fatal("failed to get devices")
			}
		} else {
			// for _, version := range []string{"9.0", "10.0", "11.0", "12.0", "13.0", "14.0", "15.0"} {
			// for _, version := range []string{"10.0", "11.0", "12.0", "13.0", "14.0", "15.0"} {
			// 	ipsws, err := download.GetAllIPSW(version)
			// 	if err != nil {
			// 		log.WithError(err).Fatal("failed to get IPSWs")
			// 	}
			// 	unique := make(map[string]bool, len(ipsws))
			// 	uniqueIPSWs := make([]download.IPSW, len(unique))
			// 	for _, i := range ipsws {
			// 		if len(i.URL) != 0 {
			// 			if !unique[i.URL] {
			// 				uniqueIPSWs = append(uniqueIPSWs, i)
			// 				unique[i.URL] = true
			// 			}
			// 		}
			// 	}
			// 	for _, ipsw := range uniqueIPSWs {
			// 		zr, err := download.NewRemoteZipReader(ipsw.URL, &download.RemoteConfig{})
			// 		if err != nil {
			// 			log.WithError(err).Fatal("failed to create remote zip reader")
			// 		}
			// 		i, err := info.ParseZipFiles(zr.File)
			// 		if err != nil {
			// 			// log.WithError(err).Fatal("failed to parse remote ipsw")
			// 			continue
			// 		}
			// 		if err := i.GetDevices(&devices); err != nil {
			// 			log.WithError(err).Fatal("failed to get devices")
			// 		}
			// 	}
			// }

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
			if err := ioutil.WriteFile(dbPath, dat, 0755); err != nil {
				log.WithError(err).Fatalf("failed to write file %s", dbPath)
			}
		} else {
			fmt.Println(string(dat))
		}
	},
}
