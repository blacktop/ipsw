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
	"os"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/appstore"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	ASProfileCmd.AddCommand(ASProfileCreateCmd)

	ASProfileCreateCmd.Flags().StringP("type", "t", "IOS_APP_DEVELOPMENT", "Profile type")
	ASProfileCreateCmd.RegisterFlagCompletionFunc("type", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return appstore.ProfileTypes, cobra.ShellCompDirectiveDefault
	})
	ASProfileCreateCmd.Flags().StringP("bundle-id", "b", "", "Board ID")
	ASProfileCreateCmd.Flags().StringSliceP("certs", "c", []string{}, "Certificate IDs")
	ASProfileCreateCmd.Flags().StringSliceP("devices", "d", []string{}, "Device IDs")
	viper.BindPFlag("appstore.profile.create.type", ASProfileCreateCmd.Flags().Lookup("type"))
	viper.BindPFlag("appstore.profile.create.bundle-id", ASProfileCreateCmd.Flags().Lookup("bundle-id"))
	viper.BindPFlag("appstore.profile.create.certs", ASProfileCreateCmd.Flags().Lookup("certs"))
	viper.BindPFlag("appstore.profile.create.devices", ASProfileCreateCmd.Flags().Lookup("devices"))
}

// ASProfileCreateCmd represents the appstore profile command
var ASProfileCreateCmd = &cobra.Command{
	Use:     "create <NAME>",
	Aliases: []string{"c"},
	Short:   "Create a new provisioning profile.",
	Args:    cobra.ExactArgs(1),
	// SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		// parent flags
		viper.BindPFlag("appstore.p8", cmd.Flags().Lookup("p8"))
		viper.BindPFlag("appstore.iss", cmd.Flags().Lookup("iss"))
		viper.BindPFlag("appstore.kid", cmd.Flags().Lookup("kid"))
		// flags
		bid := viper.GetString("appstore.profile.create.bundle-id")
		certs := viper.GetStringSlice("appstore.profile.create.certs")
		devices := viper.GetStringSlice("appstore.profile.create.devices")

		as := appstore.NewAppStore(viper.GetString("appstore.p8"), viper.GetString("appstore.iss"), viper.GetString("appstore.kid"))

		if len(bid) == 0 {
			// Pick Board ID
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

		if len(certs) == 0 {
			// Pick Certs
			cs, err := as.GetCertificates()
			if err != nil {
				return err
			}

			var choices []string
			for _, c := range cs {
				choices = append(choices, c.Attributes.Name)
			}

			var choice string
			prompt := &survey.Select{
				Message:  "Select certificates to use:",
				Options:  choices,
				PageSize: 10,
			}
			if err := survey.AskOne(prompt, &choice); err == terminal.InterruptErr {
				log.Warn("Exiting...")
				return nil
			}

			for _, c := range cs {
				if c.Attributes.Name == choice {
					certs = append(certs, c.ID)
				}
			}
		}

		if len(devices) == 0 {
			// Pick Devvices
			ds, err := as.GetDevices()
			if err != nil {
				return err
			}

			var choices []string
			for _, d := range ds {
				choices = append(choices, d.Attributes.Name)
			}

			var choice string
			prompt := &survey.Select{
				Message:  "Select devices to use:",
				Options:  choices,
				PageSize: 10,
			}
			if err := survey.AskOne(prompt, &choice); err == terminal.InterruptErr {
				log.Warn("Exiting...")
				return nil
			}

			for _, d := range ds {
				if d.Attributes.Name == choice {
					devices = append(devices, d.ID)
				}
			}
		}

		resp, err := as.CreateProfile(args[0], viper.GetString("appstore.profile.create.type"), bid, certs, devices)
		if err != nil {
			return fmt.Errorf("failed to create profile: %v", err)
		}

		fname := args[0] + ".mobileprovision"
		log.Infof("Downloading profile %s", fname)
		if err := os.WriteFile(fname, resp.Data.Attributes.ProfileContent, 0644); err != nil {
			return fmt.Errorf("failed to write profile to disk: %v", err)
		}

		return nil
	},
}
