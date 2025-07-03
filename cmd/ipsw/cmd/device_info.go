/*
Copyright © 2025 blacktop

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

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(deviceInfoCmd)

	deviceInfoCmd.Flags().StringP("name", "n", "", "Name of device to lookup info for (e.g., 'iPhone 14 Pro')")
	deviceInfoCmd.Flags().StringP("prod", "d", "", "Device to lookup info for (e.g., 'iPhone15,2')")
	deviceInfoCmd.Flags().StringP("model", "m", "", "Model to lookup info for (e.g., 'M1,1')")
	deviceInfoCmd.Flags().StringP("board", "b", "", "Board to lookup info for")
	deviceInfoCmd.Flags().StringP("cpu", "c", "", "CPID to lookup info for")
	deviceInfoCmd.Flags().StringP("platform", "p", "", "Platform to lookup info for")
	deviceInfoCmd.Flags().String("cpid", "", "CPID to lookup info for")
	deviceInfoCmd.Flags().StringP("bdid", "i", "", "BDID to lookup info for")
	deviceInfoCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	viper.BindPFlag("device-info.name", deviceInfoCmd.Flags().Lookup("name"))
	viper.BindPFlag("device-info.prod", deviceInfoCmd.Flags().Lookup("prod"))
	viper.BindPFlag("device-info.model", deviceInfoCmd.Flags().Lookup("model"))
	viper.BindPFlag("device-info.board", deviceInfoCmd.Flags().Lookup("board"))
	viper.BindPFlag("device-info.cpu", deviceInfoCmd.Flags().Lookup("cpu"))
	viper.BindPFlag("device-info.platform", deviceInfoCmd.Flags().Lookup("platform"))
	viper.BindPFlag("device-info.cpid", deviceInfoCmd.Flags().Lookup("cpid"))
	viper.BindPFlag("device-info.bdid", deviceInfoCmd.Flags().Lookup("bdid"))
	viper.BindPFlag("device-info.json", deviceInfoCmd.Flags().Lookup("json"))
}

// deviceInfoCmd represents the deviceInfo command
var deviceInfoCmd = &cobra.Command{
	Use:           "device-info",
	Aliases:       []string{"di", "dinfo", "dev-inf"},
	Short:         "Lookup device info",
	Args:          cobra.MaximumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) (err error) {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		// procs, err := info.GetProcessorDB()
		// if err != nil {
		// 	return fmt.Errorf("failed to get processor DB: %v", err)
		// }
		// _ = procs

		db, err := info.GetIpswDB()
		if err != nil {
			return err
		}

		devs := db.Query(&info.DeviceQuery{
			Name:     viper.GetString("device-info.name"),
			Prod:     viper.GetString("device-info.prod"),
			Model:    viper.GetString("device-info.model"),
			Board:    viper.GetString("device-info.board"),
			CPU:      viper.GetString("device-info.cpu"),
			Platform: viper.GetString("device-info.platform"),
			CPID:     viper.GetString("device-info.cpid"),
			BDID:     viper.GetString("device-info.bdid"),
		})

		if viper.GetBool("device-info.json") {
			dat, err := json.Marshal(devs)
			if err != nil {
				return err
			}
			fmt.Println(string(dat))
		} else {
			for _, dev := range *devs {
				fmt.Println(dev)
			}
		}

		return nil
	},
}
