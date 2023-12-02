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
	"github.com/blacktop/ipsw/pkg/appstore"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	ASBundleCapabilityCmd.AddCommand(ASBundleCapabilityAddCmd)

	ASBundleCapabilityAddCmd.Flags().String("id", "", "Bundle ID to add capability to")
	ASBundleCapabilityAddCmd.Flags().String("type", "", "Capability type")
	viper.BindPFlag("appstore.bundle.cap.add.id", ASBundleCapabilityAddCmd.Flags().Lookup("id"))
	viper.BindPFlag("appstore.bundle.cap.add.type", ASBundleCapabilityAddCmd.Flags().Lookup("type"))
}

// ASBundleCapabilityAddCmd represents the appstore cert ls command
var ASBundleCapabilityAddCmd = &cobra.Command{
	Use:           "add",
	Short:         "🚧 Enable a capability for a bundle ID",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	Hidden:        true,
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
		bid := viper.GetString("appstore.bundle.cap.add.id")
		ctype := viper.GetString("appstore.bundle.cap.add.type")
		// Validate flags
		if (viper.GetString("appstore.p8") == "" || viper.GetString("appstore.iss") == "" || viper.GetString("appstore.kid") == "") && viper.GetString("appstore.jwt") == "" {
			return fmt.Errorf("you must provide (--p8, --iss and --kid) OR --jwt")
		}

		as := appstore.NewAppStore(
			viper.GetString("appstore.p8"),
			viper.GetString("appstore.iss"),
			viper.GetString("appstore.kid"),
			viper.GetString("appstore.jwt"),
		)

		if len(bid) == 0 { // Pick Board ID
			bids, err := as.GetBundleIDs()
			if err != nil {
				return err
			}

			var choices []string
			for _, b := range bids {
				choices = append(choices, fmt.Sprintf("%s (%s)", b.Attributes.ID, b.Attributes.Name))
			}

			var choice string
			prompt := &survey.Select{
				Message:  "Select buildID to use:",
				Options:  choices,
				PageSize: 10,
			}
			if err := survey.AskOne(prompt, &choice); err == terminal.InterruptErr {
				log.Warn("Exiting...")
				return nil
			}

			for _, b := range bids {
				if strings.HasPrefix(choice, b.Attributes.ID+" (") {
					bid = b.ID
					break
				}
			}
		}

		caps, err := as.EnableCapability(bid, ctype)
		if err != nil {
			return err
		}

		log.Info("Added Capability:")
		log.Infof("%s: %s", caps.ID, caps.Attributes.CapabilityType)

		return nil
	},
}
