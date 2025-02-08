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
package ota

import (
	"encoding/json"
	"fmt"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/ota"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	OtaCmd.AddCommand(otaInfoCmd)
	otaInfoCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	viper.BindPFlag("ota.info.json", otaInfoCmd.Flags().Lookup("json"))
}

// otaInfoCmd represents the info command
var otaInfoCmd = &cobra.Command{
	Use:           "info <OTA>",
	Aliases:       []string{"i"},
	Short:         "Display OTA metadata",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		o, err := ota.Open(args[0], viper.GetString("ota.key-val"))
		if err != nil {
			return fmt.Errorf("failed to open OTA: %v", err)
		}
		inf, err := o.Info()
		if err != nil {
			return fmt.Errorf("failed to get OTA info: %v", err)
		}

		if viper.GetBool("ota.info.json") {
			dat, err := json.Marshal(inf)
			if err != nil {
				return fmt.Errorf("failed to marshal OTA info: %v", err)
			}
			fmt.Println(string(dat))
		} else {
			fmt.Println("\n[OTA Info]")
			fmt.Println("==========")
			fmt.Println(inf)
		}

		return nil

	},
}
