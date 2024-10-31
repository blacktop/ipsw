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
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	// "sort"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/devicetree"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(deviceTreeCmd)
	deviceTreeCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	deviceTreeCmd.Flags().Bool("insecure", false, "do not verify ssl certs")
	deviceTreeCmd.Flags().BoolP("summary", "s", false, "Output summary only")
	deviceTreeCmd.Flags().BoolP("json", "j", false, "Output to stdout as JSON")
	deviceTreeCmd.Flags().BoolP("remote", "r", false, "Extract from URL")
	deviceTreeCmd.Flags().StringP("filter", "f", "", "Filter DeviceTree to parse (if multiple i.e. macOS)")
	deviceTreeCmd.MarkZshCompPositionalArgumentFile(1, "DeviceTree*im4p")
	deviceTreeCmd.ValidArgsFunction = func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"im4p"}, cobra.ShellCompDirectiveFilterFileExt
	}
	viper.BindPFlag("dtree.proxy", deviceTreeCmd.Flags().Lookup("proxy"))
	viper.BindPFlag("dtree.insecure", deviceTreeCmd.Flags().Lookup("insecure"))
	viper.BindPFlag("dtree.summary", deviceTreeCmd.Flags().Lookup("summary"))
	viper.BindPFlag("dtree.json", deviceTreeCmd.Flags().Lookup("json"))
	viper.BindPFlag("dtree.remote", deviceTreeCmd.Flags().Lookup("remote"))
	viper.BindPFlag("dtree.filter", deviceTreeCmd.Flags().Lookup("filter"))
}

// deviceTreeCmd represents the deviceTree command
var deviceTreeCmd = &cobra.Command{
	Use:           "dtree <DeviceTree>",
	Aliases:       []string{"dt", "devicetree"},
	Short:         "Parse DeviceTree",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) (err error) {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		dtrees := make(map[string]*devicetree.DeviceTree)

		if viper.GetBool("dtree.remote") {
			zr, err := download.NewRemoteZipReader(args[0], &download.RemoteConfig{
				Proxy:    viper.GetString("dtree.proxy"),
				Insecure: viper.GetBool("dtree.insecure"),
			})
			if err != nil {
				return fmt.Errorf("failed to download DeviceTree: %v", err)
			}
			dtrees, err = devicetree.ParseZipFiles(zr.File)
			if err != nil {
				return fmt.Errorf("failed to extract DeviceTree: %v", err)
			}
		} else {
			var dtree *devicetree.DeviceTree

			if ok, _ := magic.IsZip(filepath.Clean(args[0])); ok {
				zr, err := zip.OpenReader(args[0])
				if err != nil {
					return fmt.Errorf("failed to open zip: %v", err)
				}
				dtrees, err = devicetree.ParseZipFiles(zr.File)
				if err != nil {
					return fmt.Errorf("failed to extract DeviceTree: %v", err)
				}
			} else if ok, _ := magic.IsImg3(args[0]); ok {
				content, err := os.ReadFile(args[0])
				if err != nil {
					return fmt.Errorf("failed to read DeviceTree: %v", err)
				}
				dtree, err = devicetree.ParseImg3Data(content)
				if err != nil {
					return fmt.Errorf("failed to extract DeviceTree: %v", err)
				}
				dtrees[args[0]] = dtree
			} else if ok, _ := magic.IsIm4p(args[0]); ok {
				content, err := os.ReadFile(args[0])
				if err != nil {
					return fmt.Errorf("failed to read DeviceTree: %v", err)
				}
				dtree, err = devicetree.ParseImg4Data(content)
				if err != nil {
					return fmt.Errorf("failed to extract DeviceTree: %v", err)
				}
				dtrees[args[0]] = dtree
			} else {
				content, err := os.ReadFile(args[0])
				if err != nil {
					return fmt.Errorf("failed to read DeviceTree: %v", err)
				}
				dtree, err = devicetree.ParseData(bytes.NewReader(content))
				if err != nil {
					return fmt.Errorf("failed to parse DeviceTree: %v", err)
				}
				dtrees[args[0]] = dtree
			}
		}

		for name, dtree := range dtrees {
			if viper.IsSet("dtree.filter") {
				if !strings.Contains(strings.ToLower(name), strings.ToLower(viper.GetString("dtree.filter"))) {
					continue
				}
			}
			log.Infof("DeviceTree: %s", name)
			if viper.GetBool("dtree.json") {
				// jq '.[ "device-tree" ].children [] | select(.product != null) | .product."product-name"'
				// jq '.[ "device-tree" ].compatible'
				// jq '.[ "device-tree" ].model'
				j, err := json.Marshal(dtree)
				if err != nil {
					return err
				}
				fmt.Println(string(j))
			} else {
				if s, err := dtree.Summary(); err == nil {
					utils.Indent(log.Info, 2)(fmt.Sprintf("Model: %s", s.ProductType))
					utils.Indent(log.Info, 2)(fmt.Sprintf("Board Config: %s", s.BoardConfig))
					utils.Indent(log.Info, 2)(fmt.Sprintf("Product Name: %s", s.ProductName))
					if len(s.SocName) > 0 {
						var deviceType string
						if len(s.DeviceType) > 0 {
							deviceType = fmt.Sprintf(" (%s)", s.DeviceType)
						}
						utils.Indent(log.Info, 2)(fmt.Sprintf("SoC Name: %s%s", s.SocName, deviceType))
					}
					if viper.GetBool("dtree.summary") {
						continue
					}
				}
				fmt.Println(dtree.String())
			}
		}

		return nil
	},
}
