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
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	// "sort"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/devicetree"
	"github.com/pkg/errors"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(deviceTreeCmd)
	deviceTreeCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	deviceTreeCmd.Flags().Bool("insecure", false, "do not verify ssl certs")
	deviceTreeCmd.Flags().BoolP("json", "j", false, "Output to stdout as JSON")
	deviceTreeCmd.Flags().BoolP("remote", "r", false, "Extract from URL")
	deviceTreeCmd.MarkZshCompPositionalArgumentFile(1, "DeviceTree*im4p")
	deviceTreeCmd.ValidArgsFunction = func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"im4p"}, cobra.ShellCompDirectiveFilterFileExt
	}
}

// deviceTreeCmd represents the deviceTree command
var deviceTreeCmd = &cobra.Command{
	Use:           "dtree <DeviceTree>",
	Aliases:       []string{"dt", "devicetree"},
	Short:         "Parse DeviceTree",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		// settings
		proxy, _ := cmd.Flags().GetString("proxy")
		insecure, _ := cmd.Flags().GetBool("insecure")
		// flags
		remoteFlag, _ := cmd.Flags().GetBool("remote")
		asJSON, _ := cmd.Flags().GetBool("json")

		if remoteFlag {
			zr, err := download.NewRemoteZipReader(args[0], &download.RemoteConfig{
				Proxy:    proxy,
				Insecure: insecure,
			})
			if err != nil {
				return errors.Wrap(err, "failed to create new remote zip reader")
			}
			dtrees, err := devicetree.ParseZipFiles(zr.File)
			if err != nil {
				return errors.Wrap(err, "failed to extract DeviceTree")
			}
			if asJSON {
				for fileName, dtree := range dtrees {
					j, err := json.Marshal(dtree)
					if err != nil {
						return err
					}
					fileName = strings.TrimSuffix(fileName, filepath.Ext(fileName))
					err = os.WriteFile(fileName+".json", j, 0660)
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
					utils.Indent(log.Info, 2)(fmt.Sprintf("Model: %s", s.ProductType))
					utils.Indent(log.Info, 2)(fmt.Sprintf("Board Config: %s", s.BoardConfig))
					utils.Indent(log.Info, 2)(fmt.Sprintf("Product Name: %s", s.ProductName))
				}
			}
		} else {
			content, err := os.ReadFile(args[0])
			if err != nil {
				return errors.Wrap(err, "failed to read DeviceTree")
			}

			var dtree *devicetree.DeviceTree
			if bytes.Contains(content[:4], []byte("3gmI")) {
				dtree, err = devicetree.ParseImg3Data(content)
				if err != nil {
					return errors.Wrap(err, "failed to extract DeviceTree")
				}
			} else {
				dtree, err = devicetree.ParseImg4Data(content)
				if err != nil {
					return errors.Wrap(err, "failed to extract DeviceTree")
				}
			}

			if asJSON {
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
				utils.Indent(log.Info, 2)(fmt.Sprintf("Model: %s", s.ProductType))
				utils.Indent(log.Info, 2)(fmt.Sprintf("Board Config: %s", s.BoardConfig))
				utils.Indent(log.Info, 2)(fmt.Sprintf("Product Name: %s", s.ProductName))
			}
		}

		return nil
	},
}
