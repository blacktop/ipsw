/*
Copyright © 2018-2024 blacktop

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
	"github.com/blacktop/go-macho"
	mcs "github.com/blacktop/go-macho/pkg/codesign"
	cstypes "github.com/blacktop/go-macho/pkg/codesign/types"
	"github.com/blacktop/ipsw/internal/codesign"
	ents "github.com/blacktop/ipsw/internal/codesign/entitlements"
	"github.com/blacktop/ipsw/internal/codesign/resources"
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
	machoSignCmd.Flags().BoolP("ad-hoc", "a", false, "ad-hoc codesign")
	machoSignCmd.Flags().StringP("cert", "c", "", "p12 codesign with cert")
	machoSignCmd.Flags().StringP("pw", "p", "", "p12 cert password")
	machoSignCmd.Flags().StringP("ent", "e", "", "entitlements.plist file")
	machoSignCmd.Flags().StringP("ent-der", "d", "", "entitlements asn1/der file")
	machoSignCmd.Flags().BoolP("ts", "t", false, "timestamp signature")
	machoSignCmd.Flags().String("timeserver", "http://timestamp.apple.com/ts01", "timeserver URL")
	machoSignCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	machoSignCmd.Flags().Bool("insecure", false, "do not verify ssl certs")
	machoSignCmd.Flags().BoolP("overwrite", "f", false, "Overwrite file")
	machoSignCmd.Flags().StringP("output", "o", "", "Output codesigned file")
	viper.BindPFlag("macho.sign.id", machoSignCmd.Flags().Lookup("id"))
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
	RunE: func(cmd *cobra.Command, args []string) error {

		var err error
		var m *macho.File
		var infoPlistData []byte
		var resourceDirSlotHash []byte

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// flags
		id := viper.GetString("macho.sign.id")
		adHoc := viper.GetBool("macho.sign.ad-hoc")
		timestamp := viper.GetBool("macho.sign.ts")
		entitlementsPlist := viper.GetString("macho.sign.ent")
		entitlementsDER := viper.GetString("macho.sign.ent-der")
		overwrite := viper.GetBool("macho.sign.overwrite")
		output := viper.GetString("macho.sign.output")
		// verify flags
		if len(entitlementsDER) > 0 && len(entitlementsPlist) == 0 {
			return fmt.Errorf("must specify --ent with --ent-der")
		}

		machoPath := filepath.Clean(args[0])

		if info, err := os.Stat(machoPath); os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", machoPath)
		} else if info.IsDir() {
			// Is a bundle .app ///////////////////////////////////
			bundleMachoPath, err := plist.GetBinaryInApp(machoPath)
			if err != nil {
				return err
			}
			if _, err := os.Stat(filepath.Join(machoPath, resources.CodeResourcesPath)); os.IsNotExist(err) {
				log.Infof("Creating %s", filepath.Join(machoPath, resources.CodeResourcesPath))
				if err := resources.CreateCodeResources(machoPath); err != nil {
					return err
				}
			}
			// get embedded CodeResources hash
			h := sha256.New()
			crdata, err := os.ReadFile(filepath.Join(machoPath, resources.CodeResourcesPath))
			if err != nil {
				return err
			}
			if _, err := h.Write(crdata); err != nil {
				return err
			}
			resourceDirSlotHash = h.Sum(nil)
			// get non-embedded Info.plist data
			infoPlistData, err = os.ReadFile(filepath.Join(machoPath, "Contents", "Info.plist"))
			if err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					return err
				}
			}
			// bundles require secure timestamping
			timestamp = true
			// set machoPath to the binary in the bundle
			machoPath = bundleMachoPath
		}

		if ok, err := magic.IsMachO(machoPath); !ok {
			return fmt.Errorf(err.Error())
		}

		if len(output) == 0 { // sign in place
			output = machoPath
			if !confirm(output, overwrite) { // confirm overwrite
				return nil
			}
		}

		var entitlementData []byte
		var entitlementDerData []byte
		if len(entitlementsPlist) > 0 {
			entitlementData, err = os.ReadFile(entitlementsPlist)
			if err != nil {
				return fmt.Errorf("failed to read entitlements file %s: %v", entitlementsPlist, err)
			}
			if len(entitlementsDER) > 0 {
				entitlementDerData, err = os.ReadFile(entitlementsDER)
				if err != nil {
					return fmt.Errorf("failed to read entitlements asn1/der file %s: %v", entitlementsDER, err)
				}
			} else {
				entitlementDerData, err = ents.DerEncode(entitlementData)
				if err != nil {
					return fmt.Errorf("failed to asn1/der encode entitlements plist %s: %v", entitlementsPlist, err)
				}
			}
		}

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

		if fat, err := macho.OpenFat(machoPath); err == nil { // UNIVERSAL MACHO
			defer fat.Close()
			log.Infof("Codesigning %s", output)
			var slices []string
			for _, arch := range fat.Arches {
				if adHoc {
					if err := arch.File.CodeSign(&mcs.Config{
						ID:                  id,
						Flags:               cstypes.ADHOC,
						Entitlements:        entitlementData,
						EntitlementsDER:     entitlementDerData,
						InfoPlist:           infoPlistData,
						ResourceDirSlotHash: resourceDirSlotHash,
					}); err != nil {
						return fmt.Errorf("failed to codesign %s: %v", output, err)
					}
				} else {
					if err := arch.File.CodeSign(&mcs.Config{
						ID:                  id,
						Flags:               cstypes.NONE,
						Entitlements:        entitlementData,
						EntitlementsDER:     entitlementDerData,
						InfoPlist:           infoPlistData,
						ResourceDirSlotHash: resourceDirSlotHash,
						CertChain:           certs,
						SignerFunction: func(data []byte) ([]byte, error) {
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
						}}); err != nil {
						return fmt.Errorf("failed to codesign MachO file: %v", err)
					}
				}
				tmp, err := os.CreateTemp("", "macho_"+arch.File.CPU.String())
				if err != nil {
					return fmt.Errorf("failed to create temp file: %v", err)
				}
				defer os.Remove(tmp.Name())
				if err := arch.File.Save(tmp.Name()); err != nil {
					return fmt.Errorf("failed to save temp file: %v", err)
				}
				if err := tmp.Close(); err != nil {
					return fmt.Errorf("failed to close temp file: %v", err)
				}
				slices = append(slices, tmp.Name())
			}
			// write signed fat file
			if ff, err := macho.CreateFat(output, slices...); err != nil {
				return fmt.Errorf("failed to create fat file: %v", err)
			} else {
				defer ff.Close()
			}
		} else { // SINGLE MACHO ARCH
			if errors.Is(err, macho.ErrNotFat) {
				m, err = macho.Open(machoPath)
				if err != nil {
					return err
				}
				defer m.Close()
				if adHoc {
					log.Infof("Ad-hoc Codesigning %s", output)
					if err := m.CodeSign(&mcs.Config{
						ID:                  id,
						Flags:               cstypes.ADHOC,
						Entitlements:        entitlementData,
						EntitlementsDER:     entitlementDerData,
						InfoPlist:           infoPlistData,
						ResourceDirSlotHash: resourceDirSlotHash,
					}); err != nil {
						return fmt.Errorf("failed to codesign MachO file: %v", err)
					}
				} else {
					log.Infof("Codesigning %s", output)
					if err := m.CodeSign(&mcs.Config{
						ID:                  id,
						Flags:               cstypes.NONE,
						Entitlements:        entitlementData,
						EntitlementsDER:     entitlementDerData,
						InfoPlist:           infoPlistData,
						ResourceDirSlotHash: resourceDirSlotHash,
						CertChain:           certs,
						SignerFunction: func(data []byte) ([]byte, error) {
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
						}}); err != nil {
						return fmt.Errorf("failed to codesign MachO file: %v", err)
					}
				}
			} else {
				return fmt.Errorf("failed to open MachO file: %v", err)
			}
			// write signed file
			if err := m.Save(output); err != nil {
				return fmt.Errorf("failed to save signed MachO file: %v", err)
			}
		}

		if runtime.GOOS == "darwin" {
			out, err := utils.CodesignShow(output)
			if err != nil {
				return err
			}
			log.Debugf("New CODESIGNATURE:\n%s", out)
			out, err = utils.CodesignVerify(output)
			if err != nil {
				return err
			}
			log.Debugf("CODESIGNATURE Verify:\n%s", out)
		}

		return nil
	},
}
