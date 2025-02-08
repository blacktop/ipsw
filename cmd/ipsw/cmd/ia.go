//go:build darwin

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
package cmd

import (
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(iaCmd)
}

// iaCmd represents the ia command
var iaCmd = &cobra.Command{
	Use:           "ia",
	Short:         "Parse InstallAssistant.pkg",
	Long:          "Currently only extracts the SharedSupport.dmg from the InstallAssistant.pkg and mounts it for you to then extract the OTA.",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	Hidden:        true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		tmpDir, err := os.MkdirTemp(os.TempDir(), "InstallAssistant")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmpDir)

		log.Info("Extracting InstallAssistant.pkg...")
		outDir, err := utils.PkgUtilExpand(filepath.Clean(args[0]), tmpDir)
		if err != nil {
			return err
		}

		dmgPath := filepath.Join(outDir, "SharedSupport.dmg")

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
					utils.Indent(log.Error, 3)(fmt.Sprintf("failed to unmount %s at %s: %v", dmgPath, mountPoint, err))
				}
			}()
		}

		var zips []string
		if err := filepath.Walk(filepath.Join(mountPoint, "com_apple_MobileAsset_MacSoftwareUpdate"), func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				return fmt.Errorf("prevent panic by handling failure accessing a path %q: %v", path, err)
			}
			if info.IsDir() {
				return nil
			}
			if filepath.Ext(path) == ".zip" && filepath.Base(path) != "UpdateBrain.zip" {
				zips = append(zips, path)
			}
			return nil
		}); err != nil {
			return err
		}

		if len(zips) == 0 {
			return fmt.Errorf("no OTA zips found in %s", mountPoint)
		}

		for _, z := range zips {
			utils.Indent(log.WithFields(log.Fields{
				"zip": z,
			}).Info, 2)("OTA")
		}

		utils.Indent(log.Info, 2)(fmt.Sprintf("Run:\n\tipsw ota ls %s | grep \"dyld\\|cryptex-system\"", zips[0]))

		// block until user hits ctrl-c
		done := make(chan os.Signal, 1)
		signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
		utils.Indent(log.Info, 3)(fmt.Sprintf("Press Ctrl+C to unmount '%s' ...", mountPoint))
		<-done

		return nil
	},
}
