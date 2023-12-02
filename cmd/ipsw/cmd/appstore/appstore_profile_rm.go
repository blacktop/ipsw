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
	ASProfileCmd.AddCommand(ASProfileRemoveCmd)

	ASProfileRemoveCmd.Flags().String("id", "", "Profile ID to renew")
	ASProfileRemoveCmd.Flags().StringP("name", "n", "", "Profile name to renew")
	viper.BindPFlag("appstore.profile.rm.id", ASProfileRemoveCmd.Flags().Lookup("id"))
	viper.BindPFlag("appstore.profile.rm.name", ASProfileRemoveCmd.Flags().Lookup("name"))
}

// ASProfileRemoveCmd represents the appstore profile rm command
var ASProfileRemoveCmd = &cobra.Command{
	Use:           "rm",
	Short:         "Delete a provisioning profile that is used for app development or distribution",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		var profile *appstore.Profile

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
		id := viper.GetString("appstore.profile.rm.id")
		name := viper.GetString("appstore.profile.rm.name")
		// Validate flags
		if (viper.GetString("appstore.p8") == "" || viper.GetString("appstore.iss") == "" || viper.GetString("appstore.kid") == "") && viper.GetString("appstore.jwt") == "" {
			return fmt.Errorf("you must provide (--p8, --iss and --kid) OR --jwt")
		}
		if id != "" && name != "" {
			return fmt.Errorf("cannot use both --id and --name")
		}

		as := appstore.NewAppStore(
			viper.GetString("appstore.p8"),
			viper.GetString("appstore.iss"),
			viper.GetString("appstore.kid"),
			viper.GetString("appstore.jwt"),
		)

		if id != "" || name != "" {
			if id != "" {
				profile, err = as.GetProfile(id)
				if err != nil {
					return err
				}
			} else {
				profs, err := as.GetProfiles()
				if err != nil {
					return err
				}
				for _, prof := range profs {
					if prof.Attributes.Name == name {
						profile = &prof
						break
					}
				}
				if profile == nil {
					return fmt.Errorf("failed to find profile with name '%s'", name)
				}
			}
		} else {
			profs, err := as.GetProfiles()
			if err != nil {
				return err
			}

			var choices []string
			for _, prof := range profs {
				choices = append(choices, fmt.Sprintf("%s: %s (%s), Expires: %s", prof.ID, prof.Attributes.Name, prof.Attributes.ProfileState, prof.Attributes.ExpirationDate.Format("02Jan2006 15:04:05")))
			}

			var choice string
			prompt := &survey.Select{
				Message:  "Select provisioning profile to renew:",
				Options:  choices,
				PageSize: 10,
			}
			if err := survey.AskOne(prompt, &choice); err == terminal.InterruptErr {
				log.Warn("Exiting...")
				return nil
			}

			for _, prof := range profs {
				if strings.HasPrefix(choice, prof.ID+":") {
					profile = &prof
					break
				}
			}
		}

		log.Infof("Deleting Profile %s", profile.Attributes.Name)
		return as.DeleteProfile(profile.ID)
	},
}
