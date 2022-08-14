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
	"os"
	"text/tabwriter"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/usb/apps"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	AppsCmd.AddCommand(idevAppsListCmd)
	idevAppsListCmd.Flags().BoolP("system", "s", false, "List system apps")
	idevAppsListCmd.Flags().BoolP("user", "r", false, "List user apps")
	idevAppsListCmd.Flags().BoolP("json", "j", false, "Display apps as JSON")
}

// idevAppsListCmd represents the list command
var idevAppsListCmd = &cobra.Command{
	Use:           "ls",
	Short:         "List installed applications",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		udid, _ := cmd.Flags().GetString("udid")
		system, _ := cmd.Flags().GetBool("system")
		user, _ := cmd.Flags().GetBool("user")
		asJSON, _ := cmd.Flags().GetBool("json")

		if system && user {
			return fmt.Errorf("cannot list system and user apps at the same time")
		}

		if len(udid) == 0 {
			dev, err := utils.PickDevice()
			if err != nil {
				return fmt.Errorf("failed to pick USB connected devices: %w", err)
			}
			udid = dev.UniqueDeviceID
		}

		cli, err := apps.NewClient(udid)
		if err != nil {
			return fmt.Errorf("failed to connect to apps client: %w", err)
		}
		defer cli.Close()

		iapps, err := cli.Lookup()
		if err != nil {
			return fmt.Errorf("failed to get installed apps: %w", err)
		}

		// filter apps
		var filtered []*apps.AppBundle
		for _, a := range iapps {
			if system && a.ApplicationType == "System" {
				filtered = append(filtered, a)
			} else if user && a.ApplicationType == "User" {
				filtered = append(filtered, a)
			} else if !system && !user {
				filtered = append(filtered, a)
			}
		}

		if len(filtered) == 0 {
			return fmt.Errorf("no apps found")
		}

		if asJSON {
			appsJSON, err := json.Marshal(filtered)
			if err != nil {
				return fmt.Errorf("failed to marshal apps to JSON: %s", err)
			}
			fmt.Println(string(appsJSON))
		} else {
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
			for _, a := range filtered {
				if len(a.CFBundleIdentifier) > 0 {
					fmt.Fprintf(w, "%s\n", a)
				}
			}
			w.Flush()
		}
		return nil
	},
}
