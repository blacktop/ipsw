/*
Copyright © 2018-2026 blacktop

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
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/apex/log"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/commands/mount"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
	viper.BindPFlag("mdevs.pem-db", mdevsCmd.Flags().Lookup("pem-db"))
}

// mdevsCmd represents the mdevs command
var mdevsCmd = &cobra.Command{
	Use:           "mdevs <IPSW>",
	Aliases:       []string{"md", "mobiledevices"},
	Short:         "List all MobileDevices in IPSW",
	SilenceErrors: true,
	Args:          cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"ipsw"}, cobra.ShellCompDirectiveFilterFileExt
	},
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		pemDB := viper.GetString("mdevs.pem-db")

		ipswPath := filepath.Clean(args[0])

		return listMobileDevices(mount.NewSession(ipswPath, &mount.Config{PemDB: pemDB}), cmd.OutOrStdout())
	},
}

type mobileDeviceMountSession interface {
	Root(string) (string, error)
	Close() error
}

func listMobileDevices(session mobileDeviceMountSession, output io.Writer) (err error) {
	defer func() {
		if closeErr := session.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("failed to close mount session: %w", closeErr))
		}
	}()
	mountPoint, err := session.Root("fs")
	if err != nil {
		return fmt.Errorf("failed to mount filesystem DMG: %w", err)
	}
	mountPoint = utils.MountedFilesystemRoot(mountPoint)

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
		w := tabwriter.NewWriter(output, 0, 0, 3, ' ', 0)
		for _, v := range md.UTExportedTypeDeclarations {
			if v.TagSpec != nil {
				fmt.Fprintf(w, "%s:\t%s\t%s\t%s\n", v.ID, v.Description, v.ConformsTo, v.TagSpec["com.apple.device-model-code"])
			}
		}
		if err := w.Flush(); err != nil {
			return fmt.Errorf("failed to write MobileDevices: %w", err)
		}
	}

	return nil
}
