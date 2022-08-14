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
package idev

import (
	"encoding/json"
	"fmt"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/usb/diagnostics"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DiagCmd.AddCommand(idevDiagIOregCmd)
	idevDiagIOregCmd.Flags().StringP("plane", "p", "", "Current Plane")
	idevDiagIOregCmd.Flags().StringP("name", "n", "", "Entry Name")
	idevDiagIOregCmd.Flags().StringP("class", "c", "", "Entry Class")
}

// idevDiagIOregCmd represents the ioreg command
var idevDiagIOregCmd = &cobra.Command{
	Use:           "ioreg",
	Short:         "Query IORegistry",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		udid, _ := cmd.Flags().GetString("udid")
		plane, _ := cmd.Flags().GetString("plane")
		name, _ := cmd.Flags().GetString("name")
		class, _ := cmd.Flags().GetString("class")

		if len(udid) == 0 {
			dev, err := utils.PickDevice()
			if err != nil {
				return fmt.Errorf("failed to pick USB connected devices: %w", err)
			}
			udid = dev.UniqueDeviceID
		}

		cli, err := diagnostics.NewClient(udid)
		if err != nil {
			return fmt.Errorf("failed to connect to diagnostics: %w", err)
		}
		defer cli.Close()

		resp, err := cli.IORegistry(plane, name, class)
		if err != nil {
			return fmt.Errorf("failed to query ioregistry: %w", err)
		}

		iorJSON, err := json.Marshal(resp)
		if err != nil {
			return fmt.Errorf("failed to marshal IORegistry response to JSON: %s", err)
		}
		fmt.Println(string(iorJSON))

		return nil
	},
}
