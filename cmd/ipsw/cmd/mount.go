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
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/commands/mount"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/spf13/cobra"
)

var mountCmdSubCmds = []string{"fs", "sys", "app"}

func init() {
	rootCmd.AddCommand(mountCmd)
}

// mountCmd represents the mount command
var mountCmd = &cobra.Command{
	Use:           "mount [fs|sys|app] IPSW",
	Aliases:       []string{"mo", "mnt"},
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

		mctx, err := mount.DmgInIPSW(args[1], args[0])
		if err != nil {
			return fmt.Errorf("failed to mount %s DMG: %v", args[0], err)
		}

		if mctx.AlreadyMounted {
			log.Infof("%s DMG already mounted at %s", args[0], mctx.MountPoint)
		} else {
			log.Infof("Mounted %s DMG %s", args[0], filepath.Base(mctx.DmgPath))
		}

		// block until user hits ctrl-c
		done := make(chan os.Signal, 1)
		signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
		utils.Indent(log.Info, 2)(fmt.Sprintf("Press Ctrl+C to unmount '%s' ...", mctx.MountPoint))
		<-done

		utils.Indent(log.Info, 2)(fmt.Sprintf("Unmounting %s", mctx.MountPoint))
		return mctx.Unmount()
	},
}
