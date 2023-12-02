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

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/appstore"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	ASDeviceCmd.AddCommand(ASDeviceRegisterCmd)

	ASDeviceRegisterCmd.Flags().StringP("name", "n", "", "Device name")
	ASDeviceRegisterCmd.Flags().StringP("platform", "t", "IOS", "Device platform")
	ASDeviceRegisterCmd.Flags().StringP("udid", "u", "", "Device UDID")
	viper.BindPFlag("appstore.device.reg.name", ASDeviceRegisterCmd.Flags().Lookup("name"))
	viper.BindPFlag("appstore.device.reg.platform", ASDeviceRegisterCmd.Flags().Lookup("platform"))
	viper.BindPFlag("appstore.device.reg.udid", ASDeviceRegisterCmd.Flags().Lookup("udid"))
}

// ASDeviceRegisterCmd represents the appstore device reg command
var ASDeviceRegisterCmd = &cobra.Command{
	Use:           "reg",
	Aliases:       []string{"r"},
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
		name := viper.GetString("appstore.device.reg.name")
		platform := viper.GetString("appstore.device.reg.platform")
		udid := viper.GetString("appstore.device.reg.udid")
		// Validate flags
		if (viper.GetString("appstore.p8") == "" || viper.GetString("appstore.iss") == "" || viper.GetString("appstore.kid") == "") && viper.GetString("appstore.jwt") == "" {
			return fmt.Errorf("you must provide (--p8, --iss and --kid) OR --jwt")
		}
		if name == "" || platform == "" || udid == "" {
			return fmt.Errorf("you must provide --name, --platform AND --udid")
		}
		as := appstore.NewAppStore(
			viper.GetString("appstore.p8"),
			viper.GetString("appstore.iss"),
			viper.GetString("appstore.kid"),
			viper.GetString("appstore.jwt"),
		)

		dev, err := as.RegisterDevice(name, platform, udid)
		if err != nil {
			return err
		}

		log.Info("Registered NEW device:")
		model := dev.Attributes.DeviceClass
		if dev.Attributes.Model != "" {
			model = dev.Attributes.Model
		}
		utils.Indent(log.Info, 2)(fmt.Sprintf("%s: [%s] Added: %s - %s (%s)", dev.ID, dev.Attributes.Status, dev.Attributes.AddedDate.Format("02Jan2006 15:04:05"), dev.Attributes.Name, model))

		return nil
	},
}
