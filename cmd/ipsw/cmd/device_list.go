// +build linux,!cgo windows,!cgo darwin,cgo

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
	"sort"
	"strconv"
	"strings"

	"github.com/blacktop/ipsw/pkg/xcode"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

func init() {
	deviceCmd.AddCommand(listCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// listCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	listCmd.Flags().BoolP("gen", "", false, "Generate device_traits.json file")
}

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all iOS devices",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {

		gen, _ := cmd.Flags().GetBool("gen")
		if gen {
			devices, err := xcode.ReadDeviceTraitsDB()
			if err != nil {
				return err
			}

			err = xcode.WriteToJSON(devices)
			if err != nil {
				return err
			}

			return nil
		}

		devices, err := xcode.GetDevices()
		if err != nil {
			return err
		}

		sort.Sort(xcode.ByProductType{devices})

		data := [][]string{}
		for _, device := range devices {
			data = append(data, []string{
				device.ProductType,
				strings.Replace(device.ProductDescription, "generation", "gen", 1),
				device.DeviceTrait.PreferredArchitecture,
				strconv.Itoa(device.DeviceTrait.DevicePerformanceMemoryClass),
			})
		}

		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Product", "Description", "Architecture", "Memory(GB)"})
		table.AppendBulk(data)
		table.SetAlignment(tablewriter.ALIGN_LEFT)
		table.Render() // Send output

		return nil
	},
}
