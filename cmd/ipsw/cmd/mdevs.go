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
package cmd

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/aea"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/spf13/cobra"
)

type typeDecl struct {
	ID          string         `plist:"UTTypeIdentifier,omitempty"`
	Description string         `plist:"UTTypeDescription,omitempty"`
	IconFile    string         `plist:"UTTypeIconFile,omitempty"`
	ConformsTo  any            `plist:"UTTypeConformsTo,omitempty"`
	TagSpec     map[string]any `plist:"UTTypeTagSpecification,omitempty"`
}
type MobileDevice struct {
	UTExportedTypeDeclarations []typeDecl `plist:"UTExportedTypeDeclarations,omitempty"`
}

func init() {
	rootCmd.AddCommand(mdevsCmd)

	mdevsCmd.Flags().String("pem-db", "", "AEA pem DB JSON file")
}

// mdevsCmd represents the mdevs command
var mdevsCmd = &cobra.Command{
	Use:           "mdevs",
	Aliases:       []string{"md", "mobiledevices"},
	Short:         "List all MobileDevices in IPSW",
	SilenceUsage:  true,
	SilenceErrors: true,
	Args:          cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"ipsw"}, cobra.ShellCompDirectiveFilterFileExt
	},
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		pemDB, _ := cmd.Flags().GetString("pem-db")

		ipswPath := filepath.Clean(args[0])

		i, err := info.Parse(ipswPath)
		if err != nil {
			return fmt.Errorf("failed to parse IPSW: %v", err)
		}

		dmgPath, err := i.GetFileSystemOsDmg()
		if err != nil {
			return fmt.Errorf("failed to get filesystem DMG: %v", err)
		}

		// check if filesystem DMG already exists (due to previous mount command)
		if _, err := os.Stat(dmgPath); os.IsNotExist(err) {
			// extract filesystem DMG
			dmgs, err := utils.Unzip(ipswPath, "", func(f *zip.File) bool {
				return strings.EqualFold(filepath.Base(f.Name), dmgPath)
			})
			if err != nil {
				return fmt.Errorf("failed to extract %s from IPSW: %v", dmgPath, err)
			}
			if len(dmgs) == 0 {
				return fmt.Errorf("failed to find %s in IPSW", dmgPath)
			}
			defer os.Remove(dmgs[0])
		} else {
			log.Debugf("Found extracted %s", dmgPath)
		}
		if filepath.Ext(dmgPath) == ".aea" {
			dmgPath, err = aea.Decrypt(&aea.DecryptConfig{
				Input:  dmgPath,
				Output: filepath.Dir(dmgPath),
				PemDB:  pemDB,
			})
			if err != nil {
				return fmt.Errorf("failed to parse AEA encrypted DMG: %v", err)
			}
			defer os.Remove(dmgPath)
		}
		// mount filesystem DMG
		log.Debugf("Mounting %s", dmgPath)
		mountPoint, alreadyMounted, err := utils.MountDMG(dmgPath)
		if err != nil {
			return fmt.Errorf("failed to mount DMG: %v", err)
		}
		if alreadyMounted {
			utils.Indent(log.Debug, 2)(fmt.Sprintf("%s already mounted", dmgPath))
		} else {
			defer func() {
				log.Debugf("Unmounting %s", dmgPath)
				if err := utils.Retry(3, 2*time.Second, func() error {
					return utils.Unmount(mountPoint, true)
				}); err != nil {
					log.Errorf("failed to unmount %s at %s: %v", dmgPath, mountPoint, err)
				}
			}()
		}

		pattern := filepath.Join(mountPoint, "System/Library/CoreServices/CoreTypes.bundle/Contents/Library/MobileDevice*")
		mobileDevices, err := filepath.Glob(pattern)
		if err != nil {
			return fmt.Errorf("failed to glob MobileDevices: %v", err)
		}
		if len(mobileDevices) == 0 { // try NEW pattern
			pattern = filepath.Join(mountPoint, "System/Library/Templates/Data/System/Library/CoreServices/CoreTypes.bundle/Contents/Library/MobileDevices*")
			mobileDevices, err = filepath.Glob(pattern)
			if err != nil {
				return fmt.Errorf("failed to glob MobileDevices: %v", err)
			}
			if len(mobileDevices) == 0 { // try the host macOS
				mobileDevices, err = filepath.Glob("/System/Library/CoreServices/CoreTypes.bundle/Contents/Library/MobileDevices*")
				if err != nil {
					return fmt.Errorf("failed to glob MobileDevices: %v", err)
				}
			}
		}

		for _, mobileDevice := range mobileDevices {
			log.Info(mobileDevice)
			infoPlistPath := filepath.Join(mobileDevice, "Info.plist")
			if _, err := os.Stat(infoPlistPath); os.IsNotExist(err) {
				infoPlistPath = filepath.Join(mobileDevice, "Contents/Info.plist")
			}
			dat, err := os.ReadFile(infoPlistPath)
			if err != nil {
				return fmt.Errorf("failed to read Info.plist: %v", err)
			}
			var md MobileDevice
			if err := plist.NewDecoder(bytes.NewReader(dat)).Decode(&md); err != nil {
				return fmt.Errorf("failed to decode Info.plist: %v", err)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			for _, v := range md.UTExportedTypeDeclarations {
				if v.TagSpec != nil {
					fmt.Fprintf(w, "%s:\t%s\t%s\t%s\n", v.ID, v.Description, v.ConformsTo, v.TagSpec["com.apple.device-model-code"])
				}
			}
			w.Flush()
		}

		return nil
	},
}
