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
package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/commands/mount"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(mountCmd)

	mountCmd.Flags().StringP("key", "k", "", "DMG key")
	mountCmd.Flags().Bool("lookup", false, "Lookup DMG keys on theapplewiki.com")
	mountCmd.Flags().String("pem-db", "", "AEA pem DB JSON file")
}

// mountCmd represents the mount command
var mountCmd = &cobra.Command{
	Use:           "mount [fs|sys|app|exc] IPSW",
	Aliases:       []string{"mo", "mnt"},
	Short:         "Mount DMG from IPSW",
	SilenceUsage:  true,
	SilenceErrors: true,
	Args:          cobra.ExactArgs(2),
	Example: heredoc.Doc(`
		# Mount the filesystem DMG from an IPSW
		$ ipsw mount fs iPhone15,2_16.5_20F66_Restore.ipsw

		# Mount the system DMG with a specific decryption key
		$ ipsw mount sys iPhone.ipsw --key "a1b2c3d4e5f6..."

		# Mount fs DMG and lookup keys from theapplewiki.com
		$ ipsw mount fs iPod5,1_7.1.2_11D257_Restore.ipsw --lookup

		# Mount dyld shared cache (exc) DMG with AEA pem DB
		$ ipsw mount exc iPhone.ipsw --pem-db /path/to/pem.json
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
		key, _ := cmd.Flags().GetString("key")
		lookupKeys, _ := cmd.Flags().GetBool("lookup")
		pemDB, _ := cmd.Flags().GetString("pem-db")
		// validate flags
		if len(key) > 0 && lookupKeys {
			return fmt.Errorf("cannot use --key AND --lookup flags together")
		}

		var keys any
		if lookupKeys {
			var (
				device  string
				version string
				build   string
			)
			re := regexp.MustCompile(`(?P<device>.+)_(?P<version>.+)_(?P<build>.+)_(?i)Restore\.ipsw$`)
			if re.MatchString(args[1]) {
				matches := re.FindStringSubmatch(args[1])
				if len(matches) < 4 {
					return fmt.Errorf("failed to parse IPSW filename: %s", args[1])
				}
				device = filepath.Base(matches[1])
				version = matches[2]
				build = matches[3]
			} else {
				return fmt.Errorf("failed to parse IPSW filename: %s", args[1])
			}
			if device == "" || build == "" {
				return fmt.Errorf("device or build information is missing from IPSW filename (required for key lookup)")
			}
			log.Info("Downloading Keys...")
			wikiKeys, err := download.GetWikiFirmwareKeys(&download.WikiConfig{
				Keys:    true,
				Device:  strings.Replace(device, "ip", "iP", 1),
				Version: version,
				Build:   strings.ToUpper(build),
				// Beta:    viper.GetBool("download.key.beta"),
			}, "", false)
			if err != nil {
				return fmt.Errorf("failed querying theapplewiki.com: %v", err)
			}
			keys = wikiKeys
		} else if len(key) > 0 {
			keys = key
		}

		mctx, err := mount.DmgInIPSW(args[1], args[0], pemDB, keys)
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
