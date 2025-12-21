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
package dyld

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"

	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var mgLookup map[string]MG

var chars = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")

var skip = []string{
	"AMFDRCreateWithOptions",
	"AMFDRDecodeCertificate",
	"AMFDRDecodeTrustObject",
	"AmountRestoreAvailable",
	"AppleBiometricServices",
	"BBUpdaterExtremeCreate",
	"BluetoothLE2Capability",
	"CoverglassSerialNumber",
	"DeviceSupportsSWProRes",
	"FloatingLiveAppOverlay",
	"IOAccessoryManagerType",
	"IOPlatformExpertDevice",
	"IOPlatformSerialNumber",
	"RegionalBehaviorNoVOIP",
	"RegionalBehaviorNoWiFi",
	"SpeakerCalibrationMiGa",
	"SpeakerCalibrationSpGa",
	"SpeakerCalibrationSpTS",
}

func generateCombinations(prefix string, length int, c chan string) {
	if length == 0 {
		c <- prefix
		return
	}
	for _, char := range chars {
		generateCombinations(prefix+string(char), length-1, c)
	}
}

func obfuscateKey(key string) string {
	md5Hash := md5.Sum([]byte("MGCopyAnswer" + key))
	return base64.StdEncoding.EncodeToString(md5Hash[:])[:22]
}

func bruteForce(targets []string, length int) bool {
	found := false
	attempts := make(chan string)
	go func() {
		defer close(attempts)
		generateCombinations("", length, attempts)
	}()
	for attempt := range attempts {
		if slices.Contains(targets, obfuscateKey(attempt)) {
			found = true
			utils.Indent(log.WithFields(log.Fields{
				"obfuscated": obfuscateKey(attempt),
				"key":        attempt,
			}).Info, 2)("Brute Forced")
			mgLookup[obfuscateKey(attempt)] = MG{
				Key: attempt,
			}
		}
	}
	return found
}

type MG struct {
	Key         string `json:"key"`
	Description string `json:"desc"`
}

func init() {
	DyldCmd.AddCommand(dyldMgCmd)

	dyldMgCmd.Flags().IntP("length", "l", 0, "Length of MG key to brute force")
	viper.BindPFlag("dyld.mg.length", dyldMgCmd.Flags().Lookup("length"))
}

// dyldMgCmd represents the mg command
var dyldMgCmd = &cobra.Command{
	Use:   "mg <DSC> <MG_JSON>",
	Short: "List MobileGestalt Keys",
	Args:  cobra.ExactArgs(2),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) == 1 {
			return []string{"json"}, cobra.ShellCompDirectiveFilterFileExt
		}
		return getDSCs(toComplete), cobra.ShellCompDirectiveDefault
	},
	SilenceErrors: true,
	Hidden:        true,
	RunE: func(cmd *cobra.Command, args []string) error {

		length := viper.GetInt("dyld.mg.length")

		dscPath := filepath.Clean(args[0])

		fileInfo, err := os.Lstat(dscPath)
		if err != nil {
			return fmt.Errorf("file %s does not exist", dscPath)
		}

		// Check if file is a symlink
		if fileInfo.Mode()&os.ModeSymlink != 0 {
			symlinkPath, err := os.Readlink(dscPath)
			if err != nil {
				return errors.Wrapf(err, "failed to read symlink %s", dscPath)
			}
			// TODO: this seems like it would break
			linkParent := filepath.Dir(dscPath)
			linkRoot := filepath.Dir(linkParent)

			dscPath = filepath.Join(linkRoot, symlinkPath)
		}

		f, err := dyld.Open(dscPath)
		if err != nil {
			return err
		}
		defer f.Close()

		libMobileGestalt, err := f.Image("libMobileGestalt.dylib")
		if err != nil {
			return err
		}

		m, err := libMobileGestalt.GetMacho()
		if err != nil {
			return err
		}

		mgData, err := os.ReadFile(filepath.Clean(args[1]))
		if err != nil {
			return err
		}

		if err := json.Unmarshal(mgData, &mgLookup); err != nil {
			return err
		}

		// TODO: this is for adding new keys from the `ipsw ent` dump for 'com.apple.private.MobileGestalt.AllowedProtectedKeys'
		// `ipsw ent IPSW --ent 'com.apple.private.MobileGestalt.AllowedProtectedKeys' | grep "-" | sort -n | uniq`
		// for _, key := range lookHere {
		// 	o := obfuscateKey(key)
		// 	if mg, ok := mgLookup[o]; !ok {
		// 		if _, ok := mgLookup[key]; !ok {
		// 			mgLookup[o] = MG{
		// 				Key: key,
		// 			}
		// 		}
		// 	} else {
		// 		if mg.Key == "" {
		// 			mgLookup[o] = MG{
		// 				Key: key,
		// 			}
		// 		}
		// 	}
		// }

		count := 0
		newMGs := 0

		re := regexp.MustCompile(`^[a-zA-Z0-9+/]{22}$`)
		if cfstrs, err := m.GetCFStrings(); err == nil {
			for _, cfstr := range cfstrs {
				if re.MatchString(cfstr.Name) {
					if !slices.Contains(skip, cfstr.Name) {
						if _, ok := mgLookup[cfstr.Name]; !ok {
							log.Infof("Adding %s", cfstr.Name)
							mgLookup[cfstr.Name] = MG{} // add empty MG entry for NEW obfuscated key
							newMGs++
						}
						count++
					}
				}
			}
		}

		log.Infof("Found %d obfuscated MG Keys (%d NEW)", count, newMGs)

		total := 0
		var mysteries []string
		for o, mg := range mgLookup {
			if mg.Key == "" {
				mysteries = append(mysteries, o)
			}
			total++
		}

		utils.Indent(log.WithFields(log.Fields{
			"total":    total,
			"unknown":  len(mysteries),
			"complete": fmt.Sprintf("%.2f%%", 100*(float64(total-len(mysteries))/float64(total))),
		}).Info, 2)("MobileGestalt DB")

		if newMGs > 0 {
			cont := false
			prompt := &survey.Confirm{
				Message: "You are about to update the MG JSON with NEW obfuscated MG Keys. Continue?",
			}
			survey.AskOne(prompt, &cont)

			if cont {
				out, err := json.Marshal(mgLookup)
				if err != nil {
					return err
				}
				log.Infof("Updating MG JSON file %s with %d NEW obfuscated MG Keys", args[1], newMGs)
				if err := os.WriteFile(filepath.Clean(args[1]), out, 0644); err != nil {
					return err
				}
			}
		}

		if length > 0 {
			log.WithField("length", length).Info("Brute forcing MG keys")
			if bruteForce(mysteries, length) {
				cont := false
				prompt := &survey.Confirm{
					Message: "You are about to update the MG JSON with brute forced keys (you can test with 'ipsw idev diag mg --keys'). Continue?",
				}
				survey.AskOne(prompt, &cont)

				if cont {
					out, err := json.Marshal(mgLookup)
					if err != nil {
						return err
					}
					log.Infof("Updating MG JSON file %s with NEW brute forced keys", args[1])
					if err := os.WriteFile(filepath.Clean(args[1]), out, 0644); err != nil {
						return err
					}
				}
			} else {
				utils.Indent(log.Warn, 2)("No MG keys found")
			}
		}

		return nil
	},
}
