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
	"os"
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
	ASProvisionCmd.AddCommand(ASProvisionGenerateCmd)

	ASProvisionGenerateCmd.Flags().StringP("type", "t", "development", "Type of profile to manage (development, adhoc, distribution)")
	ASProvisionGenerateCmd.Flags().Bool("csr", false, "Create a NEW Certificate Signing Request")
	ASProvisionGenerateCmd.Flags().StringP("email", "e", "", "Email address to use for the certificate")
	ASProvisionGenerateCmd.Flags().StringP("country", "c", "US", "Country code for certificate subject (e.g., US, GB)")
	ASProvisionGenerateCmd.Flags().Bool("install", false, "Install the certificate and profile")
	ASProvisionGenerateCmd.Flags().StringP("output", "o", "", "Folder to save files to")
	ASProvisionGenerateCmd.MarkFlagDirname("output")
	viper.BindPFlag("appstore.provision.gen.type", ASProvisionGenerateCmd.Flags().Lookup("type"))
	viper.BindPFlag("appstore.provision.gen.csr", ASProvisionGenerateCmd.Flags().Lookup("csr"))
	viper.BindPFlag("appstore.provision.gen.email", ASProvisionGenerateCmd.Flags().Lookup("email"))
	viper.BindPFlag("appstore.provision.gen.country", ASProvisionGenerateCmd.Flags().Lookup("country"))
	viper.BindPFlag("appstore.provision.gen.install", ASProvisionGenerateCmd.Flags().Lookup("install"))
	viper.BindPFlag("appstore.provision.gen.output", ASProvisionGenerateCmd.Flags().Lookup("output"))
}

// ASProvisionGenerateCmd represents the provision command
var ASProvisionGenerateCmd = &cobra.Command{
	Use:     "gen <BUNDLE_ID>",
	Aliases: []string{"g", "create"},
	Short:   "Download/Create priv key, certificate & provisioning profile for Xcode signing",
	Long: `Downloads or creates the necessary certificate and provisioning profile
from App Store Connect for a given bundle ID, based on the specified type
(development, adhoc, distribution). It then optionally installs them locally
for Xcode code signing.`,
	Args: cobra.MaximumNArgs(1),
	// SilenceUsage:  true,
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
		certType := viper.GetString("appstore.provision.gen.type")
		csr := viper.GetBool("appstore.provision.gen.csr")
		email := viper.GetString("appstore.provision.gen.email")
		country := viper.GetString("appstore.provision.gen.country")
		install := viper.GetBool("appstore.provision.gen.install")
		outputDir := viper.GetString("appstore.provision.gen.output")
		// validate flags
		if (viper.GetString("appstore.p8") == "" || viper.GetString("appstore.iss") == "" || viper.GetString("appstore.kid") == "") && viper.GetString("appstore.jwt") == "" {
			return fmt.Errorf("you must provide (--p8, --iss and --kid) OR --jwt")
		}
		if csr && email == "" {
			return fmt.Errorf("you must provide --email when using --csr")
		}
		certTypeLower := strings.ToLower(certType)
		if certTypeLower != "adhoc" && certTypeLower != "development" && certTypeLower != "distribution" {
			return fmt.Errorf("invalid type '%s', must be one of: development, adhoc, distribution", certType)
		}

		as := appstore.NewAppStore(
			viper.GetString("appstore.p8"),
			viper.GetString("appstore.iss"),
			viper.GetString("appstore.kid"),
			viper.GetString("appstore.jwt"),
		)

		var bundleID string

		if len(args) == 0 {
			bundles, err := as.GetBundleIDs()
			if err != nil {
				return fmt.Errorf("failed to get bundle IDs: %w", err)
			}
			var choices []string
			for _, b := range bundles {
				choices = append(choices, fmt.Sprintf("%s (%s)", b.Attributes.ID, b.Attributes.Name))
			}

			var choice string
			prompt := &survey.Select{
				Message:  "Select Build ID to use:",
				Options:  choices,
				PageSize: 10,
			}
			if err := survey.AskOne(prompt, &choice); err == terminal.InterruptErr {
				log.Warn("Exiting...")
				return nil
			}

			for _, b := range bundles {
				if strings.HasPrefix(choice, b.Attributes.ID+" (") {
					bundleID = b.ID
					break
				}
			}
		} else {
			bundleID = args[0]
		}

		if len(outputDir) > 0 {
			if err := os.MkdirAll(outputDir, 0755); err != nil {
				return fmt.Errorf("failed creating output directory %s: %w", outputDir, err)
			}
		}

		log.WithFields(log.Fields{
			"bundle": bundleID,
			"type":   certType,
		}).Infof("Starting provision signing file creation process")

		if err := as.ProvisionSigningFiles(&appstore.ProvisionSigningFilesConfig{
			CertType: certType,
			BundleID: bundleID,
			CSR:      csr,
			Email:    email,
			Country:  country,
			Install:  install,
			Output:   outputDir,
		}); err != nil {
			return fmt.Errorf("failed to get provision signing files: %w", err)
		}

		return nil
	},
}
