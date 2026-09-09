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
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/AlecAivazis/survey/v2"
	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/commands/mount"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

func init() {
	rootCmd.AddCommand(mountCmd)

	mountCmd.Flags().StringP("key", "k", "", "DMG key")
	mountCmd.Flags().Bool("lookup", false, "Lookup DMG keys on theapplewiki.com")
	mountCmd.Flags().String("pem-db", "", "AEA pem DB JSON file")
	mountCmd.Flags().StringP("mount-point", "m", "", "Custom mount point (default: /tmp/<dmg>.mount)")
	mountCmd.Flags().String("device", "", "Device product type or board to mount (e.g. Mac18,5 or j873gap)")
	mountCmd.Flags().String("ident", "", "Identity Variant to select specific RestoreRamDisk (e.g. 'Erase', 'Upgrade', 'Recovery')")
	mountCmd.Flags().BoolP("detach", "d", false, "Mount without blocking (leave mounted in background)")
	viper.BindPFlag("mount.key", mountCmd.Flags().Lookup("key"))
	viper.BindPFlag("mount.lookup", mountCmd.Flags().Lookup("lookup"))
	viper.BindPFlag("mount.pem-db", mountCmd.Flags().Lookup("pem-db"))
	viper.BindPFlag("mount.mount-point", mountCmd.Flags().Lookup("mount-point"))
	viper.BindPFlag("mount.device", mountCmd.Flags().Lookup("device"))
	viper.BindPFlag("mount.ident", mountCmd.Flags().Lookup("ident"))
	viper.BindPFlag("mount.detach", mountCmd.Flags().Lookup("detach"))
}

// mountCmd represents the mount command
var mountCmd = &cobra.Command{
	Use:           fmt.Sprintf("mount [%s] IPSW", strings.Join(mount.DmgTypes, "|")),
	Aliases:       []string{"mo", "mnt"},
	Short:         "Mount DMG from IPSW",
	Long:          "Mount DMG from IPSW. When multiple SystemOS images are present, choose one interactively or select a target with --device.",
	SilenceErrors: true,
	Args:          cobra.ExactArgs(2),
	Example: heredoc.Doc(`
		# Mount the filesystem DMG from an IPSW
		$ ipsw mount fs iPhone15,2_16.5_20F66_Restore.ipsw

		# Mount the system DMG with a specific decryption key
		$ ipsw mount sys iPhone.ipsw --key "a1b2c3d4e5f6..."

		# Select a device-specific SystemOS image
		$ ipsw mount sys UniversalMac.ipsw --device Mac18,5

		# Mount fs DMG and lookup keys from theapplewiki.com
		$ ipsw mount fs iPod5,1_7.1.2_11D257_Restore.ipsw --lookup

		# Mount dyld shared cache (exc) DMG with AEA pem DB
		$ ipsw mount exc iPhone.ipsw --pem-db /path/to/pem.json

		# Mount to a custom mount point
		$ ipsw mount fs iPhone.ipsw --mount-point /mnt/ios-filesystem

		# Mount a RestoreRamDisk by identity (defaults to the first if not specified)
		$ ipsw mount rdisk iPhone.ipsw --ident Erase

		# Mount the RosettaOS cryptex DMG from a macOS IPSW (macOS 27+)
		$ ipsw mount rosetta UniversalMac.ipsw

		# Mount in background without blocking (detach mode)
		$ ipsw mount fs iPhone.ipsw --detach
	`),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) == 0 {
			return mount.DmgTypes, cobra.ShellCompDirectiveNoFileComp
		}
		return []string{"ipsw"}, cobra.ShellCompDirectiveFilterFileExt
	},
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		// set log level
		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		key := viper.GetString("mount.key")
		lookupKeys := viper.GetBool("mount.lookup")
		pemDB := viper.GetString("mount.pem-db")
		mountPoint := viper.GetString("mount.mount-point")
		ident := viper.GetString("mount.ident")
		detach := viper.GetBool("mount.detach")
		// validate flags
		if len(key) > 0 && lookupKeys {
			return fmt.Errorf("cannot use --key AND --lookup flags together")
		}
		cmd.SilenceUsage = true

		var keys any
		if lookupKeys {
			log.Info("Downloading Keys...")
			wikiKeys, err := download.LookupKeysFromPath(args[1], "", false)
			if err != nil {
				return fmt.Errorf("failed to lookup keys: %v", err)
			}
			keys = wikiKeys
		} else if len(key) > 0 {
			keys = key
		}

		mctx, err := mount.DmgInIPSW(args[1], args[0], &mount.Config{
			Device:         viper.GetString("mount.device"),
			SelectSystemOS: selectMountSystemOS,
			PemDB:          pemDB,
			Keys:           keys,
			MountPoint:     mountPoint,
			Ident:          ident,
		})
		if err != nil {
			return fmt.Errorf("failed to mount %s DMG: %w", args[0], err)
		}

		if mctx.AlreadyMounted {
			log.Infof("%s DMG already mounted at %s", args[0], mctx.MountPoint)
		} else {
			log.Infof("Mounted %s DMG %s", args[0], filepath.Base(mctx.DmgPath))
		}

		if detach {
			utils.Indent(log.Info, 2)(fmt.Sprintf("Detaching, run `hdiutil detach %s` to unmount manually", mctx.MountPoint))
			return nil
		} else {
			// block until user hits ctrl-c
			done := make(chan os.Signal, 1)
			signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
			utils.Indent(log.Info, 2)(fmt.Sprintf("Press Ctrl+C to unmount '%s' ...", mctx.MountPoint))
			<-done

			utils.Indent(log.Info, 2)(fmt.Sprintf("Unmounting %s", mctx.MountPoint))
			return mctx.Unmount()
		}
	},
}

func selectMountSystemOS(dmgs []info.SystemOSDMG) (int, error) {
	options := make([]string, 0, len(dmgs))
	for _, dmg := range dmgs {
		options = append(options, dmg.String())
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stderr.Fd())) {
		return 0, fmt.Errorf("multiple SystemOS images found; select a target with --device: %s",
			strings.Join(options, "; "))
	}
	var selected int
	if err := survey.AskOne(&survey.Select{
		Message: "Select a SystemOS image:",
		Options: options,
	}, &selected, survey.WithStdio(os.Stdin, os.Stderr, os.Stderr)); err != nil {
		return 0, fmt.Errorf("SystemOS image selection canceled: %w", err)
	}
	return selected, nil
}
