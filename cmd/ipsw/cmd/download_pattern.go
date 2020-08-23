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
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
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

		ipsws, err := filterIPSWs(cmd)
		if err != nil {
			log.Fatal(err.Error())
		}

		log.Debug("URLs to Download:")
		for _, i := range ipsws {
			utils.Indent(log.Debug, 2)(i.URL)
		}

		for _, i := range ipsws {

			log.WithFields(log.Fields{
				"device":  i.Identifier,
				"build":   i.BuildID,
				"version": i.Version,
				"signed":  i.Signed,
			}).Infof("Getting files that contain: %s", args[0])

			zr, err := download.NewRemoteZipReader(i.URL, &download.RemoteConfig{
				Proxy:    proxy,
				Insecure: insecure,
			})
			if err != nil {
				return errors.Wrap(err, "failed to download kernelcaches from remote ipsw")
			}

			ipsw, err := info.ParseZipFiles(zr.File)
			if err != nil {
				return errors.Wrap(err, "failed to download kernelcaches from remote ipsw")
			}

			for _, f := range zr.File {
				folder := ipsw.GetFolderForFile(path.Base(f.Name))
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

		return nil
	},
}
