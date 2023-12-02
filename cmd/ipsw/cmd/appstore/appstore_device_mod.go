/*
Copyright © 2018-2023 blacktop

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
package appstore

import (
	"fmt"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/appstore"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	ASDeviceCmd.AddCommand(ASDeviceModifyCmd)

	ASDeviceModifyCmd.Flags().String("id", "", "Device ID")
	ASDeviceModifyCmd.Flags().StringP("name", "n", "", "Device name")
	ASDeviceModifyCmd.Flags().StringP("status", "s", "ENABLED", "Device status (ENABLED|DISABLED))")
	ASDeviceModifyCmd.RegisterFlagCompletionFunc("status", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"ENABLED", "DISABLED"}, cobra.ShellCompDirectiveDefault
	})
	viper.BindPFlag("appstore.device.mod.id", ASDeviceModifyCmd.Flags().Lookup("id"))
	viper.BindPFlag("appstore.device.mod.name", ASDeviceModifyCmd.Flags().Lookup("name"))
	viper.BindPFlag("appstore.device.mod.status", ASDeviceModifyCmd.Flags().Lookup("status"))
}

// ASDeviceModifyCmd represents the appstore device reg command
var ASDeviceModifyCmd = &cobra.Command{
	Use:           "mod",
	Aliases:       []string{"m"},
	Short:         "Register a new device for app development",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// parent flags
		viper.BindPFlag("appstore.p8", cmd.Flags().Lookup("p8"))
		viper.BindPFlag("appstore.iss", cmd.Flags().Lookup("iss"))
		viper.BindPFlag("appstore.kid", cmd.Flags().Lookup("kid"))
		viper.BindPFlag("appstore.jwt", cmd.Flags().Lookup("jwt"))
		// flags
		id := viper.GetString("appstore.device.mod.id")
		name := viper.GetString("appstore.device.mod.name")
		status := viper.GetString("appstore.device.mod.status")
		// Validate flags
		if (viper.GetString("appstore.p8") == "" || viper.GetString("appstore.iss") == "" || viper.GetString("appstore.kid") == "") && viper.GetString("appstore.jwt") == "" {
			return fmt.Errorf("you must provide (--p8, --iss and --kid) OR --jwt")
		}
		if name == "" || status == "" {
			return fmt.Errorf("you must provide --name AND --status")
		}

		as := appstore.NewAppStore(
			viper.GetString("appstore.p8"),
			viper.GetString("appstore.iss"),
			viper.GetString("appstore.kid"),
			viper.GetString("appstore.jwt"),
		)

		if id == "" { // prompt for device
			devs, err := as.GetDevices()
			if err != nil {
				return err
			}

			var choices []string
			for _, d := range devs {
				choices = append(choices, fmt.Sprintf("%s: %s", d.ID, d.Attributes.Name))
			}

			var choice string
			prompt := &survey.Select{
				Message:  "Select device to modify:",
				Options:  choices,
				PageSize: 10,
			}
			if err := survey.AskOne(prompt, &choice); err == terminal.InterruptErr {
				log.Warn("Exiting...")
				return nil
			}

			for _, d := range devs {
				if strings.HasPrefix(choice, d.ID+": ") {
					id = d.ID
					break
				}
			}
		}

		dev, err := as.ModifyDevice(id, name, status)
		if err != nil {
			return err
		}

		log.Info("Modified device:")
		model := dev.Attributes.DeviceClass
		if dev.Attributes.Model != "" {
			model = dev.Attributes.Model
		}
		utils.Indent(log.Info, 2)(fmt.Sprintf("%s: [%s] Added: %s - %s (%s)", dev.ID, dev.Attributes.Status, dev.Attributes.AddedDate.Format("02Jan2006 15:04:05"), dev.Attributes.Name, model))

		return nil
	},
}
