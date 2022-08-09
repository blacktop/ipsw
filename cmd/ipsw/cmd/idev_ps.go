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
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
	"github.com/blacktop/ipsw/pkg/usb/ostrace"
	"github.com/spf13/cobra"
)

func init() {
	idevCmd.AddCommand(iDevPsCmd)

	iDevPsCmd.Flags().StringP("proc", "p", "", "process to get pid for")
}

// iDevPsCmd represents the ps command
var iDevPsCmd = &cobra.Command{
	Use:           "ps",
	Short:         "Process list",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		uuid, _ := cmd.Flags().GetString("uuid")
		proc, _ := cmd.Flags().GetString("proc")

		var err error
		var dev *lockdownd.DeviceValues
		if len(uuid) == 0 {
			dev, err = utils.PickDevice()
			if err != nil {
				return fmt.Errorf("failed to pick USB connected devices: %w", err)
			}
		} else {
			ldc, err := lockdownd.NewClient(uuid)
			if err != nil {
				return fmt.Errorf("failed to connect to lockdownd: %w", err)
			}
			defer ldc.Close()

			dev, err = ldc.GetValues()
			if err != nil {
				return fmt.Errorf("failed to get device values for %s: %w", uuid, err)
			}
		}

		cli := ostrace.NewClient(dev.UniqueDeviceID)

		pids, err := cli.PidList()
		if err != nil {
			return fmt.Errorf("failed to get pid list: %w", err)
		}

		if len(proc) > 0 {
			for pid, process := range pids {
				if strings.EqualFold(process, proc) {
					fmt.Println(pid)
				}
			}
		} else {
			// sort by pid
			keys := make([]string, 0, len(pids))
			for k := range pids {
				keys = append(keys, k)
			}
			sort.Slice(keys, func(i, j int) bool {
				numA, _ := strconv.Atoi(keys[i])
				numB, _ := strconv.Atoi(keys[j])
				return numA < numB
			})

			for _, k := range keys {
				fmt.Printf("%3s:\t%s\n", k, pids[k])
			}
		}

		return nil
	},
}
