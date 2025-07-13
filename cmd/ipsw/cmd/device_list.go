/*
Copyright © 2018-2025 blacktop

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
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/blacktop/ipsw/pkg/table"
	"github.com/blacktop/ipsw/pkg/xcode"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func init() {
	rootCmd.AddCommand(deviceListCmd)
}

// deviceListCmd represents the deviceList command
var deviceListCmd = &cobra.Command{
	Use:     "device-list",
	Aliases: []string{"devs"},
	Short:   "List all iOS devices",
	Args:    cobra.NoArgs,
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

		sort.Sort(xcode.ByProductType{Devices: devices})

		data := [][]string{}
		for _, device := range devices {
			data = append(data, []string{
				device.ProductType,
				device.Target,
				strings.Replace(device.ProductDescription, "generation", "gen", 1),
				device.Platform,
				device.DeviceTrait.PreferredArchitecture,
				strconv.Itoa(device.DeviceTrait.DevicePerformanceMemoryClass),
			})
		}

		headers := []string{"Product", "Model", "Description", "CPU", "Arch", "MemClass"}

		if term.IsTerminal(int(os.Stdout.Fd())) && term.IsTerminal(int(os.Stdin.Fd())) {
			// Use the fancy interactive BubbleTable
			model := table.NewInteractiveTable(headers, data, false)
			p := tea.NewProgram(model, tea.WithAltScreen())
			if _, err := p.Run(); err != nil {
				return fmt.Errorf("error running interactive table: %w", err)
			}
		} else {
			// Fallback to static styled table for non-TTY environments
			bubbleTable := table.NewBubbleTable(headers, false)
			bubbleTable.SetData(data)
			fmt.Println(bubbleTable.RenderStatic())
		}

		return nil
	},
}
