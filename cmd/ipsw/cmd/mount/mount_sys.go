//go:build darwin

/*
Copyright © 2022 blacktop

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
package mount

import (
	"archive/zip"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	MountCmd.AddCommand(sysCmd)
}

// sysCmd represents the sys command
var sysCmd = &cobra.Command{
	Use:           "sys",
	Short:         "Mount SystemOS DMG",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		ipswPath := filepath.Clean(args[0])

		i, err := info.Parse(ipswPath)
		if err != nil {
			return fmt.Errorf("failed to parse IPSW: %v", err)
		}

		if fsOS, err := i.GetSystemOsDmg(); err == nil {
			log.Info("Found SystemOS DMG")
			// extract systemOS DMG
			dmgs, err := utils.Unzip(ipswPath, "", func(f *zip.File) bool {
				return strings.EqualFold(filepath.Base(f.Name), fsOS)
			})
			if err != nil {
				return fmt.Errorf("failed to extract %s from IPSW: %v", fsOS, err)
			}
			if len(dmgs) == 0 {
				return fmt.Errorf("failed to find %s in IPSW", fsOS)
			}
			defer os.Remove(dmgs[0])
			// mount systemOS DMG
			utils.Indent(log.Info, 2)(fmt.Sprintf("Mounting %s", dmgs[0]))
			mountPoint, err := utils.MountFS(dmgs[0])
			if err != nil {
				return fmt.Errorf("failed to mount DMG: %v", err)
			}
			defer func() {
				utils.Indent(log.Info, 2)(fmt.Sprintf("Unmounting %s", dmgs[0]))
				if err := utils.Unmount(mountPoint, false); err != nil {
					log.Errorf("failed to unmount DMG at %s: %v", dmgs[0], err)
				}
			}()
			// block until user hits ctrl-c
			done := make(chan os.Signal, 1)
			signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
			utils.Indent(log.Info, 3)("Press Ctrl+C to unmount and destroy the temporary DMG...")
			<-done
		} else {
			return fmt.Errorf("failed to get SystemOS DMG: %v", err)
		}

		return nil
	},
}
