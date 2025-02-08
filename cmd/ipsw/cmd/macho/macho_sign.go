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
package macho

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/apex/log"
	mcs "github.com/blacktop/go-macho/pkg/codesign"
	cstypes "github.com/blacktop/go-macho/pkg/codesign/types"
	"github.com/blacktop/ipsw/internal/codesign"
	ents "github.com/blacktop/ipsw/internal/codesign/entitlements"
	"github.com/blacktop/ipsw/internal/codesign/resources"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/plist"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	MachoCmd.AddCommand(machoSignCmd)

	machoSignCmd.Flags().StringP("id", "i", "", "sign with identifier")
	machoSignCmd.Flags().StringP("team", "t", "", "sign with team id")
	machoSignCmd.Flags().BoolP("ad-hoc", "a", false, "ad-hoc codesign")
	machoSignCmd.Flags().StringP("cert", "c", "", "p12 codesign with cert")
	machoSignCmd.Flags().StringP("pw", "p", "", "p12 cert password")
	machoSignCmd.Flags().StringP("ent", "e", "", "entitlements.plist file")
	machoSignCmd.Flags().StringP("ent-der", "d", "", "entitlements asn1/der file")
	machoSignCmd.Flags().Bool("ts", false, "timestamp signature")
	machoSignCmd.Flags().String("timeserver", "http://timestamp.apple.com/ts01", "timeserver URL")
	machoSignCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	machoSignCmd.Flags().Bool("insecure", false, "do not verify ssl certs")
	machoSignCmd.Flags().BoolP("overwrite", "f", false, "Overwrite file")
	machoSignCmd.Flags().StringP("output", "o", "", "Output codesigned file")
	viper.BindPFlag("macho.sign.id", machoSignCmd.Flags().Lookup("id"))
	viper.BindPFlag("macho.sign.team", machoSignCmd.Flags().Lookup("team"))
	viper.BindPFlag("macho.sign.ad-hoc", machoSignCmd.Flags().Lookup("ad-hoc"))
	viper.BindPFlag("macho.sign.cert", machoSignCmd.Flags().Lookup("cert"))
	viper.BindPFlag("macho.sign.pw", machoSignCmd.Flags().Lookup("pw"))
	viper.BindPFlag("macho.sign.ent", machoSignCmd.Flags().Lookup("ent"))
	viper.BindPFlag("macho.sign.ent-der", machoSignCmd.Flags().Lookup("ent-der"))
	viper.BindPFlag("macho.sign.ts", machoSignCmd.Flags().Lookup("ts"))
	viper.BindPFlag("macho.sign.timeserver", machoSignCmd.Flags().Lookup("timeserver"))
	viper.BindPFlag("macho.sign.proxy", machoSignCmd.Flags().Lookup("proxy"))
	viper.BindPFlag("macho.sign.insecure", machoSignCmd.Flags().Lookup("insecure"))
	viper.BindPFlag("macho.sign.overwrite", machoSignCmd.Flags().Lookup("overwrite"))
	viper.BindPFlag("macho.sign.output", machoSignCmd.Flags().Lookup("output"))
}

// machoSignCmd represents the macho sign command
var machoSignCmd = &cobra.Command{
	Use:     "sign <MACHO>",
	Aliases: []string{"sn"},
	Short:   "Codesign a MachO",
	Example: `  # Ad-hoc codesign a MachO w/ entitlements
  ❯ ipsw macho sign --id com.apple.ls --ad-hoc --ent entitlements.plist <MACHO>`,
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) (err error) {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// flags
		timestamp := viper.GetBool("macho.sign.ts")
		entitlementsPlist := viper.GetString("macho.sign.ent")
		entitlementsDER := viper.GetString("macho.sign.ent-der")
		// verify flags
		if len(entitlementsDER) > 0 && len(entitlementsPlist) == 0 {
			return fmt.Errorf("must specify --ent with --ent-der")
		}

		conf := &mcmd.SignConfig{
			Input:  filepath.Clean(args[0]),
			Output: viper.GetString("macho.sign.output"),
			Adhoc:  viper.GetBool("macho.sign.ad-hoc"),
			Codesign: &mcs.Config{
				ID:     viper.GetString("macho.sign.id"),
				TeamID: viper.GetString("macho.sign.team"),
			},
		}

		if info, err := os.Stat(conf.Input); os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", conf.Input)
		} else if info.IsDir() {
			// Is a bundle .app ///////////////////////////////////
			bundleMachoPath, err := plist.GetBinaryInApp(conf.Input)
			if err != nil {
				return err
			}
			if _, err := os.Stat(filepath.Join(conf.Input, resources.CodeResourcesPath)); os.IsNotExist(err) {
				log.Infof("Creating %s", filepath.Join(conf.Input, resources.CodeResourcesPath))
				if err := resources.CreateCodeResources(conf.Input); err != nil {
					return err
				}
			}
			// get embedded CodeResources hash
			h := sha256.New()
			crdata, err := os.ReadFile(filepath.Join(conf.Input, resources.CodeResourcesPath))
			if err != nil {
				return err
			}
			if _, err := h.Write(crdata); err != nil {
				return err
			}
			conf.Codesign.ResourceDirSlotHash = h.Sum(nil)
			// get non-embedded Info.plist data
			conf.Codesign.InfoPlist, err = os.ReadFile(filepath.Join(conf.Input, "Contents", "Info.plist"))
			if err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					return err
				}
			}
			// bundles require secure timestamping
			timestamp = true
			// set conf.Input to the binary in the bundle
			conf.Input = bundleMachoPath
		}

		if ok, err := magic.IsMachO(conf.Input); !ok {
			return fmt.Errorf(err.Error())
		}

		if len(entitlementsPlist) > 0 {
			conf.Codesign.Entitlements, err = os.ReadFile(entitlementsPlist)
			if err != nil {
				return fmt.Errorf("failed to read entitlements file %s: %v", entitlementsPlist, err)
			}
			if len(entitlementsDER) > 0 {
				conf.Codesign.EntitlementsDER, err = os.ReadFile(entitlementsDER)
				if err != nil {
					return fmt.Errorf("failed to read entitlements asn1/der file %s: %v", entitlementsDER, err)
				}
			} else {
				conf.Codesign.EntitlementsDER, err = ents.DerEncode(conf.Codesign.Entitlements)
				if err != nil {
					return fmt.Errorf("failed to asn1/der encode entitlements plist %s: %v", entitlementsPlist, err)
				}
			}
		}

		if conf.Adhoc {
			conf.Codesign.Flags = cstypes.ADHOC
		} else { // NOT ad-hoc
			var privateKey any
			var certs []*x509.Certificate
			if len(viper.GetString("macho.sign.cert")) > 0 && len(viper.GetString("macho.sign.pw")) > 0 {
				privateKey, certs, err = codesign.ParseP12(viper.GetString("macho.sign.cert"), viper.GetString("macho.sign.pw"))
				if err != nil {
					return fmt.Errorf("failed to parse p12: %v", err)
				}
				if len(certs) == 0 {
					return fmt.Errorf("no certificates found in p12")
				}
			}

			conf.Codesign.SignerFunction = func(data []byte) ([]byte, error) {
				cmsdata, err := codesign.CreateCMSSignature(data, &codesign.CMSConfig{
					CertChain:    certs,
					PrivateKey:   privateKey,
					Timestamp:    timestamp,
					TimestampURL: viper.GetString("macho.sign.timeserver"),
					Proxy:        viper.GetString("macho.sign.proxy"),
					Insecure:     viper.GetBool("macho.sign.insecure"),
				})
				if err != nil {
					return nil, fmt.Errorf("failed to create CMS signature: %v", err)
				}
				if viper.GetBool("verbose") && runtime.GOOS == "darwin" {
					fmt.Println("CMS DATA")
					fmt.Println("========")
					utils.PrintCMSData(cmsdata)
				}
				return cmsdata, nil
			}
		}

		if len(conf.Output) == 0 { // sign in place
			conf.Output = conf.Input
			if !confirm(conf.Output, viper.GetBool("macho.sign.overwrite")) { // confirm overwrite
				return nil
			}
		}

		log.Infof("Codesigning %s", conf.Output)
		if err := mcmd.Sign(conf); err != nil {
			return fmt.Errorf("failed to sign MachO file: %v", err)
		}

		if runtime.GOOS == "darwin" {
			out, err := utils.CodesignShow(conf.Output)
			if err != nil {
				return err
			}
			log.Debugf("New CODESIGNATURE:\n%s", out)
			out, err = utils.CodesignVerify(conf.Output)
			if err != nil {
				return err
			}
			log.Debugf("CODESIGNATURE Verify:\n%s", out)
		}

		return nil
	},
}
