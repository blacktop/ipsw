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
	"fmt"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/commands/extract"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(extractCmd)

	extractCmd.Flags().BoolP("remote", "r", false, "Extract from URL")
	extractCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	extractCmd.Flags().Bool("insecure", false, "do not verify ssl certs")
	extractCmd.Flags().BoolP("kernel", "k", false, "Extract kernelcache")
	extractCmd.Flags().BoolP("dyld", "d", false, "Extract dyld_shared_cache")
	extractCmd.Flags().BoolP("dtree", "t", false, "Extract DeviceTree")
	extractCmd.Flags().StringP("dmg", "m", "", "Extract DMG file (app, sys, fs)")
	extractCmd.Flags().BoolP("iboot", "i", false, "Extract iBoot")
	extractCmd.Flags().BoolP("sep", "s", false, "Extract sep-firmware")
	extractCmd.Flags().BoolP("kbag", "b", false, "Extract Im4p Keybags")
	extractCmd.Flags().BoolP("files", "f", false, "Extract File System files")
	extractCmd.Flags().String("pattern", "", "Extract files that match regex")
	extractCmd.Flags().StringP("output", "o", "", "Folder to extract files to")
	extractCmd.Flags().Bool("flat", false, "Do NOT perserve directory structure when extracting")
	extractCmd.Flags().StringArrayP("dyld-arch", "a", []string{}, "dyld_shared_cache architecture to extract")
	extractCmd.RegisterFlagCompletionFunc("dmg", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{
			"app\tAppOS",
			"sys\tSystemOS",
			"fs\tFileSystem",
		}, cobra.ShellCompDirectiveDefault
	})

	viper.BindPFlag("extract.proxy", extractCmd.Flags().Lookup("proxy"))
	viper.BindPFlag("extract.insecure", extractCmd.Flags().Lookup("insecure"))
	viper.BindPFlag("extract.remote", extractCmd.Flags().Lookup("remote"))
	viper.BindPFlag("extract.kernel", extractCmd.Flags().Lookup("kernel"))
	viper.BindPFlag("extract.dyld", extractCmd.Flags().Lookup("dyld"))
	viper.BindPFlag("extract.dtree", extractCmd.Flags().Lookup("dtree"))
	viper.BindPFlag("extract.dmg", extractCmd.Flags().Lookup("dmg"))
	viper.BindPFlag("extract.iboot", extractCmd.Flags().Lookup("iboot"))
	viper.BindPFlag("extract.sep", extractCmd.Flags().Lookup("sep"))
	viper.BindPFlag("extract.kbag", extractCmd.Flags().Lookup("kbag"))
	viper.BindPFlag("extract.files", extractCmd.Flags().Lookup("files"))
	viper.BindPFlag("extract.pattern", extractCmd.Flags().Lookup("pattern"))
	viper.BindPFlag("extract.output", extractCmd.Flags().Lookup("output"))
	viper.BindPFlag("extract.flat", extractCmd.Flags().Lookup("flat"))
	viper.BindPFlag("extract.dyld-arch", extractCmd.Flags().Lookup("dyld-arch"))
}

// extractCmd represents the extract command
var extractCmd = &cobra.Command{
	Use:           "extract <IPSW/OTA | URL>",
	Aliases:       []string{"e", "ex"},
	Short:         "Extract kernelcache, dyld_shared_cache or DeviceTree from IPSW/OTA",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"ipsw", "zip"}, cobra.ShellCompDirectiveFilterFileExt
	},
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		// validate args
		if len(viper.GetStringSlice("extract.dyld-arch")) > 0 && !viper.GetBool("extract.dyld") {
			return fmt.Errorf("--dyld-arch or -a can only be used with --dyld or -d")
		} else if viper.GetBool("extract.files") && len(viper.GetString("extract.pattern")) == 0 {
			return fmt.Errorf("--pattern or -p must be used with --files or -f")
		} else if len(viper.GetStringSlice("extract.dyld-arch")) > 0 {
			for _, arch := range viper.GetStringSlice("extract.dyld-arch") {
				if !utils.StrSliceHas([]string{"arm64", "arm64e", "x86_64", "x86_64h"}, arch) {
					return fmt.Errorf("invalid dyld_shared_cache architecture '%s' (must be: arm64, arm64e, x86_64 or x86_64h)", arch)
				}
			}
		} else if viper.GetString("extract.dmg") != "" {
			if !utils.StrSliceHas([]string{"app", "sys", "fs"}, viper.GetString("extract.dmg")) {
				return fmt.Errorf("invalid DMG type '%s' (must be: app, sys or fs)", viper.GetString("extract.dmg"))
			}
		}

		config := &extract.Config{
			IPSW:     "",
			URL:      "",
			Pattern:  viper.GetString("extract.pattern"),
			Arches:   viper.GetStringSlice("extract.dyld-arch"),
			Proxy:    viper.GetString("extract.proxy"),
			Insecure: viper.GetBool("extract.insecure"),
			DMGs:     false,
			DmgType:  viper.GetString("extract.dmg"),
			Flatten:  viper.GetBool("extract.flat"),
			Progress: true,
			Output:   viper.GetString("extract.output"),
		}

		if viper.GetBool("extract.remote") {
			config.URL = args[0]
		} else {
			config.IPSW = args[0]
		}

		if viper.GetBool("extract.kernel") {
			log.Info("Extracting kernelcache")
			if _, err := extract.Kernelcache(config); err != nil {
				return err
			}
		}

		if viper.GetBool("extract.dyld") {
			log.Info("Extracting dyld_shared_cache")
			if _, err := extract.DSC(config); err != nil {
				return err
			}
		}

		if viper.GetString("extract.dmg") != "" {
			config.DMGs = true
			if viper.GetBool("extract.remote") {
				log.Error("unable to extract File System DMG remotely (let the author know if this is something you want)")
			} else {
				log.Info("Extracting DMG")
				if _, err := extract.DMG(config); err != nil {
					return err
				}
			}
		}

		if viper.GetBool("extract.dtree") {
			log.Info("Extracting DeviceTree")
			config.Pattern = `.*DeviceTree.*im(3|4)p$`
			if _, err := extract.Search(config); err != nil {
				return err
			}
		}

		if viper.GetBool("extract.iboot") {
			log.Info("Extracting iBoot")
			config.Pattern = `.*iBoot.*im4p$`
			if _, err := extract.Search(config); err != nil {
				return err
			}
		}

		if viper.GetBool("extract.sep") {
			log.Info("Extracting sep-firmware")
			config.Pattern = `.*sep-firmware.*im4p$`
			if _, err := extract.Search(config); err != nil {
				return err
			}
		}

		if viper.GetBool("extract.kbag") {
			log.Info("Extracting im4p key bags")
			if _, err := extract.Keybags(config); err != nil {
				return err
			}
		}

		if len(viper.GetString("extract.pattern")) > 0 {
			log.Infof("Extracting files matching pattern %#v", viper.GetString("extract.pattern"))
			if viper.GetBool("extract.files") {
				config.DMGs = true
			}
			if _, err := extract.Search(config); err != nil {
				return err
			}
		}

		return nil
	},
}
