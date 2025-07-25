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
package idev

import (
	"encoding/json"
	"fmt"

	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/usb/diagnostics"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DiagCmd.AddCommand(idevDiagMobileGestaltCmd)
	idevDiagMobileGestaltCmd.Flags().StringSliceP("keys", "k", []string{}, "Keys to retrieve (can be csv)")
	idevDiagMobileGestaltCmd.MarkFlagRequired("keys")
	viper.BindPFlag("idev.diag.mg.keys", idevDiagMobileGestaltCmd.Flags().Lookup("keys"))
}

// idevDiagMobileGestaltCmd represents the mg command
var idevDiagMobileGestaltCmd = &cobra.Command{
	Use:           "mg",
	Short:         "Query MobileGestalt",
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		udid := viper.GetString("idev.udid")
		keys := viper.GetStringSlice("idev.diag.mg.keys")

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

		resp, err := cli.MobileGestalt(keys...)
		if err != nil {
			return fmt.Errorf("failed to query MobileGestalt: %w", err)
		}

		mgJSON, err := json.Marshal(resp)
		if err != nil {
			return fmt.Errorf("failed to marshal MobileGestalt response to JSON: %s", err)
		}
		fmt.Println(string(mgJSON))

		return nil
	},
	Example: `❯ ipsw idev diag mg -k SupplementalBuildVersion,ProductVersionExtra | jq .

	{
		"status": "Success",
		"diagnostics": {
		  "MobileGestalt": {
			"ProductVersionExtra": "(a)",
			"Status": "Success",
			"SupplementalBuildVersion": "20C7750490e"
		  }
		}
	  }`,
}
