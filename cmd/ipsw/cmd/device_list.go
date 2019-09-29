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

	// listCmd.Flags().BoolP("gen", "", false, "Generate device_traits.json file")
}

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all iOS devices",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {

		// gen, _ := cmd.Flags().GetBool("gen")
		// if gen {
		// 	devices, err := xcode.ReadDeviceTraitsDB()
		// 	if err != nil {
		// 		return err
		// 	}

		// 	err = xcode.WriteToJSON(devices)
		// 	if err != nil {
		// 		return err
		// 	}

		// 	return nil
		// }

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
