/*
Copyright © 2025 blacktop

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
	"github.com/blacktop/ipsw/pkg/appstore"
	"github.com/spf13/cobra"
)

func init() {
	ASProvisionCmd.AddCommand(installCmd)
}

// installCmd represents the install command
var installCmd = &cobra.Command{
	Use:           "install <CERT> <KEY> <PROFILE>",
	Short:         "Install private key, certificate & provisioning profile for Xcode signing",
	Args:          cobra.ExactArgs(3),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if err := appstore.InstallCertificateAndKey(args[0], args[1]); err != nil {
			log.Errorf("installing certificate and key: %w", err)
		}
		profile, err := appstore.InstallProvisioningProfile(args[2])
		if err != nil {
			return fmt.Errorf("installing provisioning profile: %w", err)
		}
		log.Infof("Installed provisioning profile: %s", profile)

		return nil
	},
}
