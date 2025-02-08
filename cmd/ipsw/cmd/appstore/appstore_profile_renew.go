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
package appstore

import (
	"fmt"
	"os"
	"path/filepath"
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
	ASProfileCmd.AddCommand(ASProfileRenewCmd)

	ASProfileRenewCmd.Flags().String("id", "", "Profile ID to renew")
	ASProfileRenewCmd.Flags().StringP("name", "n", "", "Profile name to renew")
	ASProfileRenewCmd.Flags().StringP("output", "o", "", "Folder to download profile to")
	ASProfileRenewCmd.MarkFlagDirname("output")
	viper.BindPFlag("appstore.profile.renew.id", ASProfileRenewCmd.Flags().Lookup("id"))
	viper.BindPFlag("appstore.profile.renew.name", ASProfileRenewCmd.Flags().Lookup("name"))
	viper.BindPFlag("appstore.profile.renew.output", ASProfileRenewCmd.Flags().Lookup("output"))
}

// ASProfileRenewCmd represents the appstore profile command
var ASProfileRenewCmd = &cobra.Command{
	Use:           "renew <NAME>",
	Aliases:       []string{"r"},
	Short:         "Renew and expired or invalide provisioning profile",
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
		id := viper.GetString("appstore.profile.renew.id")
		name := viper.GetString("appstore.profile.renew.name")
		output := viper.GetString("appstore.profile.renew.output")
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

		var bid string
		var certs []string
		var devices []string
		// get bundle id
		bundleID, err := as.GetProfileBundleID(profile.ID)
		if err != nil {
			return err
		}
		bid = bundleID.ID
		// get certs
		pCerts, err := as.GetProfileCerts(profile.ID)
		if err != nil {
			return err
		}
		for _, cert := range pCerts {
			certs = append(certs, cert.ID)
		}
		pDevs, err := as.GetProfileDevices(profile.ID)
		if err != nil {
			return err
		}
		for _, dev := range pDevs {
			devices = append(devices, dev.ID)
		}

		log.Info("Removing old profile")
		if err := as.DeleteProfile(profile.ID); err != nil {
			return fmt.Errorf("failed to delete profile: %v", err)
		}

		log.WithFields(log.Fields{
			"bundle-id": bid,
			"certs":     certs,
			"devices":   devices,
		}).Debug("Creating profile")

		resp, err := as.CreateProfile(profile.Attributes.Name, string(profile.Attributes.ProfileType), bid, certs, devices, profile.Attributes.OfflineProfile)
		if err != nil {
			return fmt.Errorf("failed to create profile: %v", err)
		}

		log.Info("Renewed Profile:")
		prof := resp.Data
		utils.Indent(log.Info, 2)(fmt.Sprintf("%s: %s (%s), Expires: %s", prof.ID, prof.Attributes.Name, prof.Attributes.ProfileState, prof.Attributes.ExpirationDate.Format("02Jan2006 15:04:05")))
		cs, err := as.GetProfileCerts(prof.ID)
		if err != nil {
			return err
		}
		if len(certs) > 0 {
			utils.Indent(log.Info, 3)("Certificates:")
		}
		for _, cert := range cs {
			utils.Indent(log.Info, 4)(fmt.Sprintf("%s: %s (%s), Expires: %s", cert.ID, cert.Attributes.Name, cert.Attributes.CertificateType, cert.Attributes.ExpirationDate.Format("02Jan2006 15:04:05")))
		}
		devs, err := as.GetProfileDevices(prof.ID)
		if err != nil {
			return err
		}
		if len(devs) > 0 {
			utils.Indent(log.Info, 3)("Devices:")
		}
		for _, dev := range devs {
			utils.Indent(log.Info, 4)(fmt.Sprintf("%s: %s (%s)", dev.ID, dev.Attributes.Name, dev.Attributes.DeviceClass))
		}

		fname := prof.Attributes.Name + ".mobileprovision"
		if output != "" {
			if err := os.MkdirAll(output, os.ModePerm); err != nil {
				return fmt.Errorf("failed to renew output directory: %v", err)
			}
			fname = filepath.Join(output, fname)
		}
		log.Infof("Downloading renewed profile to %s", fname)
		if err := os.WriteFile(fname, resp.Data.Attributes.ProfileContent, 0644); err != nil {
			return fmt.Errorf("failed to write profile to '%s': %v", fname, err)
		}

		return nil
	},
}
