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

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/appstore"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	ASCertCmd.AddCommand(ASCertAddCmd)

	ASCertAddCmd.Flags().StringP("type", "t", "", "Certificate type")
	ASCertAddCmd.RegisterFlagCompletionFunc("type", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return appstore.CertTypes, cobra.ShellCompDirectiveDefault
	})
	ASCertAddCmd.Flags().StringP("csr", "c", "", "CSR content (https://developer.apple.com/help/account/create-certificates/create-a-certificate-signing-request)")
	ASCertAddCmd.Flags().StringP("output", "o", "", "Folder to download profile to")
	ASCertAddCmd.MarkFlagDirname("output")
	viper.BindPFlag("appstore.cert.add.type", ASCertAddCmd.Flags().Lookup("type"))
	viper.BindPFlag("appstore.cert.add.csr", ASCertAddCmd.Flags().Lookup("csr"))
	viper.BindPFlag("appstore.cert.add.output", ASCertAddCmd.Flags().Lookup("output"))
}

// ASCertAddCmd represents the appstore cert ls command
var ASCertAddCmd = &cobra.Command{
	Use:           "add",
	Short:         "Create a new certificate using a certificate signing request",
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
		ctype := viper.GetString("appstore.cert.add.type")
		csr := viper.GetString("appstore.cert.add.csr")
		output := viper.GetString("appstore.cert.add.output")
		// Validate flags
		if (viper.GetString("appstore.p8") == "" || viper.GetString("appstore.iss") == "" || viper.GetString("appstore.kid") == "") && viper.GetString("appstore.jwt") == "" {
			return fmt.Errorf("you must provide (--p8, --iss and --kid) OR --jwt")
		}
		if ctype == "" || csr == "" {
			return fmt.Errorf("you must provide --type and --csr")
		}

		as := appstore.NewAppStore(
			viper.GetString("appstore.p8"),
			viper.GetString("appstore.iss"),
			viper.GetString("appstore.kid"),
			viper.GetString("appstore.jwt"),
		)

		cert, err := as.CreateCertificate(ctype, csr)
		if err != nil {
			return err
		}

		log.Info("Certificate:")
		log.Infof("%s: %s (%s), Expires: %s", cert.ID, cert.Attributes.Name, cert.Attributes.CertificateType, cert.Attributes.ExpirationDate.Format("02Jan2006 15:04:05"))
		fname := fmt.Sprintf("%s_%s.cer", cert.Attributes.Name, cert.Attributes.ExpirationDate.Format("2006-01-02"))
		if output != "" {
			if err := os.MkdirAll(output, os.ModePerm); err != nil {
				return fmt.Errorf("failed to create output directory: %v", err)
			}
			fname = filepath.Join(output, fname)
		}
		log.Infof("Downloading certificate to: %s", fname)
		return os.WriteFile(fname, cert.Attributes.CertificateContent, 0644)
	},
}
