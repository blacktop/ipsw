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
	"encoding/json"
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
	extractCmd.Flags().Bool("dtree", false, "Extract DeviceTree")
	extractCmd.Flags().String("dmg", "", "Extract DMG file (app, sys, fs)")
	extractCmd.Flags().Bool("iboot", false, "Extract iBoot")
	extractCmd.Flags().Bool("sep", false, "Extract sep-firmware")
	extractCmd.Flags().Bool("sptm", false, "Extract SPTM and TXM Firmwares")
	extractCmd.Flags().Bool("kbag", false, "Extract Im4p Keybags")
	extractCmd.Flags().Bool("sys-ver", false, "Extract SystemVersion")
	extractCmd.Flags().BoolP("files", "f", false, "Extract File System files")
	extractCmd.Flags().StringP("pattern", "p", "", "Extract files that match regex")
	extractCmd.Flags().StringP("output", "o", "", "Folder to extract files to")
	extractCmd.MarkFlagDirname("output")
	extractCmd.Flags().Bool("flat", false, "Do NOT perserve directory structure when extracting")
	extractCmd.Flags().BoolP("json", "j", false, "Output extracted paths as JSON")
	extractCmd.Flags().StringArrayP("dyld-arch", "a", []string{}, "dyld_shared_cache architecture to extract")
	extractCmd.Flags().Bool("driverkit", false, "Extract DriverKit dyld_shared_cache")
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
	viper.BindPFlag("extract.sptm", extractCmd.Flags().Lookup("sptm"))
	viper.BindPFlag("extract.kbag", extractCmd.Flags().Lookup("kbag"))
	viper.BindPFlag("extract.sys-ver", extractCmd.Flags().Lookup("sys-ver"))
	viper.BindPFlag("extract.files", extractCmd.Flags().Lookup("files"))
	viper.BindPFlag("extract.pattern", extractCmd.Flags().Lookup("pattern"))
	viper.BindPFlag("extract.output", extractCmd.Flags().Lookup("output"))
	viper.BindPFlag("extract.flat", extractCmd.Flags().Lookup("flat"))
	viper.BindPFlag("extract.json", extractCmd.Flags().Lookup("json"))
	viper.BindPFlag("extract.dyld-arch", extractCmd.Flags().Lookup("dyld-arch"))
	viper.BindPFlag("extract.driverkit", extractCmd.Flags().Lookup("driverkit"))
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
		} else if viper.GetBool("extract.files") && len(viper.GetString("extract.pattern")) == 0 {
			return fmt.Errorf("--pattern or -p must be used with --files or -f")
		} else if viper.GetBool("extract.driverkit") && !viper.GetBool("extract.dyld") {
			return fmt.Errorf("--driverkit can only be used with --dyld or -d")
		}

		config := &extract.Config{
			IPSW:      "",
			URL:       "",
			Pattern:   viper.GetString("extract.pattern"),
			Arches:    viper.GetStringSlice("extract.dyld-arch"),
			DriverKit: viper.GetBool("extract.driverkit"),
			Proxy:     viper.GetString("extract.proxy"),
			Insecure:  viper.GetBool("extract.insecure"),
			DMGs:      false,
			DmgType:   viper.GetString("extract.dmg"),
			Flatten:   viper.GetBool("extract.flat"),
			Progress:  true,
			Output:    viper.GetString("extract.output"),
		}

		if viper.GetBool("extract.remote") {
			config.URL = args[0]
		} else {
			config.IPSW = args[0]
		}

		if typ, err := extract.FirmwareType(config); err == nil {
			if typ == "OTA" {
				log.Warn("Extracting from OTA may not work (you should try the `ipsw ota extract` command)")
			}
		}

		if viper.GetBool("extract.kernel") {
			log.Info("Extracting kernelcache")
			out, err := extract.Kernelcache(config)
			if err != nil {
				return err
			}
			if viper.GetBool("extract.json") {
				dat, err := json.Marshal(out)
				if err != nil {
					return fmt.Errorf("failed to marshal output paths as JSON: %s", err)
				}
				fmt.Println(string(dat))
			} else {
				for fn := range out {
					utils.Indent(log.Info, 2)("Created " + fn)
				}
			}
		}

		if viper.GetBool("extract.dyld") {
			log.Info("Extracting dyld_shared_cache")
			out, err := extract.DSC(config)
			if err != nil {
				return err
			}
			if viper.GetBool("extract.json") {
				dat, err := json.Marshal(out)
				if err != nil {
					return fmt.Errorf("failed to marshal output paths as JSON: %s", err)
				}
				fmt.Println(string(dat))
			} else {
				for _, f := range out {
					utils.Indent(log.Info, 2)("Created " + f)
				}
			}
		}

		if viper.GetString("extract.dmg") != "" {
			config.DMGs = true
			if viper.GetBool("extract.remote") {
				log.Error("unable to extract File System DMG remotely (let the author know if this is something you want)")
			} else {
				log.Info("Extracting DMG")
				out, err := extract.DMG(config)
				if err != nil {
					return err
				}
				if viper.GetBool("extract.json") {
					dat, err := json.Marshal(out)
					if err != nil {
						return fmt.Errorf("failed to marshal output paths as JSON: %s", err)
					}
					fmt.Println(string(dat))
				} else {
					for _, f := range out {
						utils.Indent(log.Info, 2)("Created " + f)
					}
				}
			}
		}

		if viper.GetBool("extract.dtree") {
			log.Info("Extracting DeviceTree")
			config.Pattern = `.*DeviceTree.*im(3|4)p$`
			out, err := extract.Search(config)
			if err != nil {
				return err
			}
			if viper.GetBool("extract.json") {
				dat, err := json.Marshal(out)
				if err != nil {
					return fmt.Errorf("failed to marshal output paths as JSON: %s", err)
				}
				fmt.Println(string(dat))
			} else {
				for _, f := range out {
					utils.Indent(log.Info, 2)("Created " + f)
				}
			}
		}

		if viper.GetBool("extract.iboot") {
			log.Info("Extracting iBoot")
			config.Pattern = `.*iBoot.*im4p$`
			out, err := extract.Search(config)
			if err != nil {
				return err
			}
			if viper.GetBool("extract.json") {
				dat, err := json.Marshal(out)
				if err != nil {
					return fmt.Errorf("failed to marshal output paths as JSON: %s", err)
				}
				fmt.Println(string(dat))
			} else {
				for _, f := range out {
					utils.Indent(log.Info, 2)("Created " + f)
				}
			}
		}

		if viper.GetBool("extract.sep") {
			log.Info("Extracting sep-firmware")
			config.Pattern = `.*sep-firmware.*im4p$`
			out, err := extract.Search(config)
			if err != nil {
				return err
			}
			if viper.GetBool("extract.json") {
				dat, err := json.Marshal(out)
				if err != nil {
					return fmt.Errorf("failed to marshal output paths as JSON: %s", err)
				}
				fmt.Println(string(dat))
			} else {
				for _, f := range out {
					utils.Indent(log.Info, 2)("Created " + f)
				}
			}
		}

		if viper.GetBool("extract.sptm") {
			log.Info("Extracting SPTM firmware")
			out, err := extract.SPTM(config)
			if err != nil {
				return err
			}
			if viper.GetBool("extract.json") {
				dat, err := json.Marshal(out)
				if err != nil {
					return fmt.Errorf("failed to marshal output paths as JSON: %s", err)
				}
				fmt.Println(string(dat))
			} else {
				for _, f := range out {
					utils.Indent(log.Info, 2)("Created " + f)
				}
			}
		}

		if viper.GetBool("extract.kbag") {
			log.Info("Extracting im4p key bags")
			out, err := extract.Keybags(config)
			if err != nil {
				return err
			}
			utils.Indent(log.Info, 2)("Created " + out)
		}

		if viper.GetBool("extract.sys-ver") {
			log.Info("Extracting SystemVersion")
			out, err := extract.SystemVersion(config.IPSW)
			if err != nil {
				return err
			}
			dat, err := json.MarshalIndent(out, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(dat))
		}

		if len(viper.GetString("extract.pattern")) > 0 {
			log.Infof("Extracting files matching pattern %#v", viper.GetString("extract.pattern"))
			if viper.GetBool("extract.files") {
				config.DMGs = true
			}
			out, err := extract.Search(config)
			if err != nil {
				return err
			}
			if viper.GetBool("extract.json") {
				dat, err := json.Marshal(out)
				if err != nil {
					return fmt.Errorf("failed to marshal output paths as JSON: %s", err)
				}
				fmt.Println(string(dat))
			} else {
				for _, f := range out {
					utils.Indent(log.Info, 2)("Created " + f)
				}
			}
		}

		return nil
	},
}
