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

	// "sort"
	"io/ioutil"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/devicetree"
	"github.com/blacktop/ipsw/utils"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

var (
	jsonFlag   bool
	remoteFlag bool
)

func init() {
	rootCmd.AddCommand(deviceCmd)

	deviceCmd.Flags().BoolVarP(&jsonFlag, "json", "j", false, "Output to stdout as JSON")
	deviceCmd.Flags().BoolVarP(&remoteFlag, "remote", "r", false, "Extract from URL")
}

// deviceCmd represents the device command
var deviceCmd = &cobra.Command{
	Use:   "device",
	Short: "Parse DeviceTree",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		if remoteFlag {
			dtrees, err := devicetree.RemoteParse(args[0])
			if err != nil {
				return errors.Wrap(err, "failed to extract DeviceTree")
			}
			// sort.Sort(dtrees)
			for fileName, dtree := range dtrees {
				utils.Indent(log.Info, 1)(fileName)
				dtree.Summary()
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
				dtree.Summary()
			}
		}

		return nil
	},
}
