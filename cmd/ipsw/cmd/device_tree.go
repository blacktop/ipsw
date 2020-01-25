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
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	// "sort"
	"io/ioutil"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/devicetree"
	"github.com/pkg/errors"

	"github.com/spf13/cobra"
)

var (
	jsonFlag   bool
	remoteFlag bool
)

func init() {
	rootCmd.AddCommand(deviceTreeCmd)

	deviceTreeCmd.Flags().BoolVarP(&jsonFlag, "json", "j", false, "Output to stdout as JSON")
	deviceTreeCmd.Flags().BoolVarP(&remoteFlag, "remote", "r", false, "Extract from URL")

	deviceTreeCmd.MarkZshCompPositionalArgumentFile(1, "DeviceTree*")
}

// deviceTreeCmd represents the deviceTree command
var deviceTreeCmd = &cobra.Command{
	Use:   "dtree <DeviceTree>",
	Short: "Parse DeviceTree",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		if remoteFlag {
			zr, err := download.NewRemoteZipReader(args[0], &download.RemoteConfig{})
			if err != nil {
				return errors.Wrap(err, "failed to create new remote zip reader")
			}
			dtrees, err := devicetree.ParseZipFiles(zr.File)
			if err != nil {
				return errors.Wrap(err, "failed to extract DeviceTree")
			}
			if jsonFlag {
				for fileName, dtree := range dtrees {
					j, err := json.Marshal(dtree)
					if err != nil {
						return err
					}
					fileName = strings.TrimSuffix(fileName, filepath.Ext(fileName))
					err = ioutil.WriteFile(fileName+".json", j, 0644)
					if err != nil {
						return errors.Wrap(err, "failed to decompress kernelcache")
					}
				}
			} else {
				// sort.Sort(dtrees)
				for fileName, dtree := range dtrees {
					utils.Indent(log.Info, 1)(fileName)
					s, err := dtree.Summary()
					if err != nil {
						return errors.Wrap(err, "failed to parse device-tree")
					}
					utils.Indent(log.Info, 2)(fmt.Sprintf("Model: %s", s.Model))
					utils.Indent(log.Info, 2)(fmt.Sprintf("Board Config: %s", s.BoardConfig))
					utils.Indent(log.Info, 2)(fmt.Sprintf("Product Name: %s", s.ProductName))
				}
			}
		} else {
			content, err := ioutil.ReadFile(args[0])
			if err != nil {
				return errors.Wrap(err, "failed to read DeviceTree")
			}
			dtree, err := devicetree.ParseImg4Data(content)
			if err != nil {
				return errors.Wrap(err, "failed to extract DeviceTree")
			}
			if jsonFlag {
				// jq '.[ "device-tree" ].children [] | select(.product != null) | .product."product-name"'
				// jq '.[ "device-tree" ].compatible'
				// jq '.[ "device-tree" ].model'
				j, err := json.Marshal(dtree)
				if err != nil {
					return err
				}

				fmt.Println(string(j))
			} else {
				s, err := dtree.Summary()
				if err != nil {
					return errors.Wrap(err, "failed to parse device-tree")
				}
				utils.Indent(log.Info, 2)(fmt.Sprintf("Model: %s", s.Model))
				utils.Indent(log.Info, 2)(fmt.Sprintf("Board Config: %s", s.BoardConfig))
				utils.Indent(log.Info, 2)(fmt.Sprintf("Product Name: %s", s.ProductName))
			}
		}

		return nil
	},
}
