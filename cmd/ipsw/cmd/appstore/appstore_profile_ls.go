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

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/appstore"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	ASProfileCmd.AddCommand(ASProfileListCmd)
}

// ASProfileListCmd represents the appstore profile command
var ASProfileListCmd = &cobra.Command{
	Use:           "ls",
	Short:         "List provisioning profiles and download their data",
	Args:          cobra.NoArgs,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

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

		profs, err := as.GetProfiles()
		if err != nil {
			return err
		}

		log.Info("Provisioning Profiles:")
		for _, prof := range profs {
			if prof.IsExpired() || prof.IsInvalid() {
				utils.Indent(log.Error, 2)(fmt.Sprintf("%s: %s (%s), Expires: %s", prof.ID, prof.Attributes.Name, prof.Attributes.ProfileState, prof.Attributes.ExpirationDate.Format("02Jan2006 15:04:05")))
			} else {
				utils.Indent(log.Info, 2)(fmt.Sprintf("%s: %s (%s), Expires: %s", prof.ID, prof.Attributes.Name, prof.Attributes.ProfileState, prof.Attributes.ExpirationDate.Format("02Jan2006 15:04:05")))
			}
			certs, err := as.GetProfileCerts(prof.ID)
			if err != nil {
				return err
			}
			if len(certs) > 0 {
				utils.Indent(log.Info, 3)("Certificates:")
			}
			for _, cert := range certs {
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
		}

		return nil
	},
}
