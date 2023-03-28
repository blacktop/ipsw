//go:build darwin

/*
Copyright © 2018-2023 blacktop

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
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/spf13/cobra"
)

var mountCmdSubCmds = []string{"fs", "sys", "app"}

func init() {
	rootCmd.AddCommand(mountCmd)
}

// mountCmd represents the mount command
var mountCmd = &cobra.Command{
	Use:           "mount [fs|sys|app] IPSW",
	Aliases:       []string{"m", "mnt"},
	Short:         "Mount DMG from IPSW",
	SilenceUsage:  true,
	SilenceErrors: true,
	Args:          cobra.ExactArgs(2),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) == 0 {
			return mountCmdSubCmds, cobra.ShellCompDirectiveNoFileComp
		}
		return []string{"ipsw"}, cobra.ShellCompDirectiveFilterFileExt
	},
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		ipswPath := filepath.Clean(args[1])

		i, err := info.Parse(ipswPath)
		if err != nil {
			return fmt.Errorf("failed to parse IPSW: %v", err)
		}

		var dmgPath string

		switch args[0] {
		case "fs":
			dmgPath, err = i.GetFileSystemOsDmg()
			if err != nil {
				return fmt.Errorf("failed to get filesystem DMG: %v", err)
			}
			log.Info("Found Filesystem DMG")
		case "sys":
			dmgPath, err = i.GetSystemOsDmg()
			if err != nil {
				return fmt.Errorf("failed to get SystemOS DMG: %v", err)
			}
			log.Info("Found SystemOS DMG")
		case "app":
			dmgPath, err = i.GetAppOsDmg()
			if err != nil {
				return fmt.Errorf("failed to get AppOS DMG: %v", err)
			}
			log.Info("Found AppOS DMG")
		default:
			return fmt.Errorf("invalid subcommand: %s; must be one of: '%s'", args[0], strings.Join(mountCmdSubCmds, "', '"))
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
			utils.Indent(log.Debug, 2)(fmt.Sprintf("Found extracted %s", dmgPath))
		}

		// mount filesystem DMG
		utils.Indent(log.Info, 2)(fmt.Sprintf("Mounting %s", dmgPath))
		mountPoint, alreadyMounted, err := utils.MountFS(dmgPath)
		if err != nil {
			if !errors.Is(err, utils.ErrMountResourceBusy) {
				return fmt.Errorf("failed to mount DMG: %v", err)
			}
		}
		if alreadyMounted {
			utils.Indent(log.Info, 3)(fmt.Sprintf("%s already mounted", dmgPath))
		} else {
			defer func() {
				utils.Indent(log.Info, 2)(fmt.Sprintf("Unmounting %s", dmgPath))
				if err := utils.Retry(3, 2*time.Second, func() error {
					return utils.Unmount(mountPoint, false)
				}); err != nil {
					log.Errorf("failed to unmount %s at %s: %v", dmgPath, mountPoint, err)
				}
			}()
		}

		// block until user hits ctrl-c
		done := make(chan os.Signal, 1)
		signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
		utils.Indent(log.Info, 3)(fmt.Sprintf("Press Ctrl+C to unmount '%s' ...", mountPoint))
		<-done

		return nil
	},
}
