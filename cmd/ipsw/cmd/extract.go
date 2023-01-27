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
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/devicetree"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func isURL(str string) bool {
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func extractFromDMG(ipswPath, dmgPath, destPath string, pattern *regexp.Regexp) error {
	// check if filesystem DMG already exists (due to previous mount command)
	if _, err := os.Stat(dmgPath); os.IsNotExist(err) {
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
	}
	if err := utils.ExtractFromDMG(dmgPath, destPath, pattern); err != nil {
		return fmt.Errorf("failed to extract files matching pattern: %v", err)
	}

	return nil
}

func init() {
	rootCmd.AddCommand(extractCmd)

	extractCmd.Flags().BoolP("remote", "r", false, "Extract from URL")
	extractCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	extractCmd.Flags().Bool("insecure", false, "do not verify ssl certs")
	extractCmd.Flags().BoolP("kernel", "k", false, "Extract kernelcache")
	extractCmd.Flags().BoolP("dyld", "d", false, "Extract dyld_shared_cache")
	extractCmd.Flags().BoolP("dtree", "t", false, "Extract DeviceTree")
	extractCmd.Flags().BoolP("dmg", "m", false, "Extract File System DMG file")
	extractCmd.Flags().BoolP("iboot", "i", false, "Extract iBoot")
	extractCmd.Flags().BoolP("sep", "s", false, "Extract sep-firmware")
	extractCmd.Flags().BoolP("kbag", "b", false, "Extract Im4p Keybags")
	extractCmd.Flags().BoolP("files", "f", false, "Extract File System files")
	extractCmd.Flags().String("pattern", "", "Extract files that match regex")
	extractCmd.Flags().StringP("output", "o", "", "Folder to extract files to")
	extractCmd.Flags().Bool("flat", false, "Do NOT perserve directory structure when extracting")
	extractCmd.Flags().StringArrayP("dyld-arch", "a", []string{}, "dyld_shared_cache architecture to extract")

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
		}

		if viper.GetBool("extract.remote") {
			remoteURL := args[0]

			if !isURL(remoteURL) {
				log.Fatal("must supply valid URL when using the remote flag")
			}

			// Get handle to remote IPSW zip
			zr, err := download.NewRemoteZipReader(remoteURL, &download.RemoteConfig{
				Proxy:    viper.GetString("extract.proxy"),
				Insecure: viper.GetBool("extract.insecure"),
			})
			if err != nil {
				return fmt.Errorf("unable to download remote zip: %v", err)
			}

			if viper.GetBool("extract.kernel") {
				log.Info("Extracting remote kernelcache")
				if err = kernelcache.RemoteParse(zr, filepath.Clean(viper.GetString("extract.output"))); err != nil {
					return fmt.Errorf("failed to extract kernelcache from remote IPSW: %v", err)
				}
			}

			i, err := info.ParseZipFiles(zr.File)
			if err != nil {
				return fmt.Errorf("failed to parse plists in remote zip: %v", err)
			}
			folder, err := i.GetFolder()
			if err != nil {
				log.Errorf("failed to get folder from remote zip metadata: %v", err)
			}
			destPath := filepath.Join(filepath.Clean(viper.GetString("extract.output")), folder)

			if viper.GetBool("extract.dyld") {
				log.Info("Extracting remote dyld_shared_cache(s)")
				sysDMG, err := i.GetSystemOsDmg()
				if err != nil {
					return fmt.Errorf("only iOS16.x/macOS13.x supported: failed to get SystemOS DMG from remote zip metadata: %v", err)
				}
				if len(sysDMG) == 0 {
					return fmt.Errorf("only iOS16.x/macOS13.x supported: no SystemOS DMG found in remote zip metadata")
				}
				tmpDIR, err := os.MkdirTemp("", "ipsw_extract_remote_dyld")
				if err != nil {
					return fmt.Errorf("failed to create temporary directory to store SystemOS DMG: %v", err)
				}
				defer os.RemoveAll(tmpDIR)
				if err := utils.RemoteUnzip(zr.File, regexp.MustCompile(fmt.Sprintf("^%s$", sysDMG)), tmpDIR, true); err != nil {
					return fmt.Errorf("failed to extract SystemOS DMG from remote IPSW: %v", err)
				}
				if err := dyld.ExtractFromDMG(i, filepath.Join(tmpDIR, sysDMG), destPath, viper.GetStringSlice("extract.dyld-arch")); err != nil {
					return fmt.Errorf("failed to extract dyld_shared_cache(s) from remote IPSW: %v", err)
				}
			}

			if viper.GetBool("extract.dmg") {
				log.Error("unable to extract File System DMG remotely (let the author know if this is something you want)")
			}

			if viper.GetBool("extract.dtree") {
				log.Info("Extracting remote DeviceTree(s)")
				if err := utils.RemoteUnzip(zr.File, regexp.MustCompile(`.*DeviceTree.*im(3|4)p$`), destPath, viper.GetBool("extract.flat")); err != nil {
					return fmt.Errorf("failed to extract DeviceTree from remote IPSW: %v", err)
				}
			}

			if viper.GetBool("extract.iboot") {
				log.Info("Extracting remote iBoot(s)")
				if err := utils.RemoteUnzip(zr.File, regexp.MustCompile(`.*iBoot.*im4p$`), destPath, viper.GetBool("extract.flat")); err != nil {
					return fmt.Errorf("failed to extract iBoot from remote IPSW: %v", err)
				}
			}

			if viper.GetBool("extract.sep") {
				log.Info("Extracting sep-firmware(s)")
				if err := utils.RemoteUnzip(zr.File, regexp.MustCompile(`.*sep-firmware.*im4p$`), destPath, viper.GetBool("extract.flat")); err != nil {
					return fmt.Errorf("failed to extract SEPOS from remote IPSW: %v", err)
				}
			}

			if viper.GetBool("extract.kbag") {
				log.Info("Extracting im4p kbags")
				kbags, err := img4.ParseZipKeyBags(zr.File, i, viper.GetString("extract.pattern"))
				if err != nil {
					return fmt.Errorf("failed to parse im4p kbags: %v", err)
				}
				out, err := json.Marshal(kbags)
				if err != nil {
					return fmt.Errorf("failed to marshal im4p kbags: %v", err)
				}
				fmt.Println(string(out))
				os.Mkdir(destPath, 0770)
				if err := os.WriteFile(filepath.Join(destPath, "kbags.json"), out, 0660); err != nil {
					return fmt.Errorf("failed to write %s: %v", filepath.Join(destPath, "kbags.json"), err)
				}
			}

			if len(viper.GetString("extract.pattern")) > 0 {
				log.Infof("Extracting files matching pattern %#v", viper.GetString("extract.pattern"))
				validRegex, err := regexp.Compile(viper.GetString("extract.pattern"))
				if err != nil {
					return fmt.Errorf("failed to compile regexp: %v", err)
				}
				if err := utils.RemoteUnzip(zr.File, validRegex, destPath, viper.GetBool("extract.flat")); err != nil {
					return fmt.Errorf("failed to extract files matching pattern in remote IPSW: %v", err)
				}
			}
		} else { // local IPSW/OTA
			ipswPath := filepath.Clean(args[0])

			if _, err := os.Stat(ipswPath); os.IsNotExist(err) {
				return fmt.Errorf("file %s does not exist", ipswPath)
			}

			i, err := info.Parse(ipswPath)
			if err != nil {
				return fmt.Errorf("failed to parse plists in IPSW: %v", err)
			}

			folder, err := i.GetFolder()
			if err != nil {
				log.Errorf("failed to get folder from zip metadata: %v", err)
			}
			destPath := filepath.Join(filepath.Clean(viper.GetString("extract.output")), folder)

			if viper.GetBool("extract.kernel") {
				log.Info("Extracting kernelcaches")
				if err := kernelcache.Extract(ipswPath, destPath); err != nil {
					return fmt.Errorf("failed to extract kernelcaches from IPSW: %v", err)
				}
			}

			if viper.GetBool("extract.dyld") {
				log.Info("Extracting dyld_shared_cache")
				if err := dyld.Extract(ipswPath, destPath, viper.GetStringSlice("extract.dyld-arch")); err != nil {
					return fmt.Errorf("failed to extract dyld_shared_cache(s) from IPSW: %v", err)
				}
			}

			if viper.GetBool("extract.dtree") {
				log.Info("Extracting DeviceTrees")
				if err := devicetree.Extract(ipswPath, destPath); err != nil {
					return fmt.Errorf("failed to extract DeviceTrees from IPSW: %v", err)
				}
			}

			if viper.GetBool("extract.dmg") {
				fsDMG, err := i.GetFileSystemOsDmg()
				if err != nil {
					return fmt.Errorf("failed to find filesystem DMG in IPSW: %v", err)
				}
				log.Info("Extracting File System DMG")
				if _, err := utils.Unzip(ipswPath, destPath, func(f *zip.File) bool {
					return strings.EqualFold(filepath.Base(f.Name), fsDMG)
				}); err != nil {
					return fmt.Errorf("failed extract %s from IPSW: %v", fsDMG, err)
				}
				log.Infof("Created %s", filepath.Join(destPath, fsDMG))
			}

			if viper.GetBool("extract.iboot") {
				log.Info("Extracting iBoot")
				if _, err := utils.Unzip(ipswPath, destPath, func(f *zip.File) bool {
					var validIBoot = regexp.MustCompile(`.*iBoot.*im4p$`)
					return validIBoot.MatchString(f.Name)
				}); err != nil {
					return fmt.Errorf("failed extract iBoot from IPSW: %v", err)
				}
			}

			if viper.GetBool("extract.sep") {
				log.Info("Extracting sep-firmwares")
				if _, err := utils.Unzip(ipswPath, destPath, func(f *zip.File) bool {
					var validSEP = regexp.MustCompile(`.*sep-firmware.*im4p$`)
					return validSEP.MatchString(f.Name)
				}); err != nil {
					return fmt.Errorf("failed to extract sep-firmwares from IPSW: %v", err)
				}
			}

			if viper.GetBool("extract.kbag") {
				log.Info("Extracting im4p kbags")
				zr, err := zip.OpenReader(ipswPath)
				if err != nil {
					return fmt.Errorf("failed to open zip: %v", err)
				}
				defer zr.Close()
				kbags, err := img4.ParseZipKeyBags(zr.File, i, viper.GetString("extract.pattern"))
				if err != nil {
					return fmt.Errorf("failed to parse im4p kbags: %v", err)
				}
				out, err := json.Marshal(kbags)
				if err != nil {
					return fmt.Errorf("failed to marshal im4p kbags: %v", err)
				}
				fmt.Println(string(out))
				os.Mkdir(destPath, 0770)
				if err := os.WriteFile(filepath.Join(destPath, "kbags.json"), out, 0660); err != nil {
					return fmt.Errorf("failed to write %s: %v", filepath.Join(destPath, "kbags.json"), err)
				}
			}

			if len(viper.GetString("extract.pattern")) > 0 {
				log.Infof("Extracting files matching pattern %#v", viper.GetString("extract.pattern"))
				patternRE, err := regexp.Compile(viper.GetString("extract.pattern"))
				if err != nil {
					return fmt.Errorf("failed to compile regexp: %v", err)
				}

				if viper.GetBool("extract.files") { // SEARCH THE DMGs
					if appOS, err := i.GetAppOsDmg(); err == nil {
						if err := extractFromDMG(ipswPath, appOS, destPath, patternRE); err != nil {
							return fmt.Errorf("failed to extract files from AppOS %s: %v", appOS, err)
						}
					}
					if systemOS, err := i.GetSystemOsDmg(); err == nil {
						if err := extractFromDMG(ipswPath, systemOS, destPath, patternRE); err != nil {
							return fmt.Errorf("failed to extract files from SystemOS %s: %v", systemOS, err)
						}
					}
					if fsOS, err := i.GetFileSystemOsDmg(); err == nil {
						if err := extractFromDMG(ipswPath, fsOS, destPath, patternRE); err != nil {
							return fmt.Errorf("failed to extract files from filesystem %s: %v", fsOS, err)
						}
					}
				} else { // SEARCH THE ZIP
					zr, err := zip.OpenReader(ipswPath)
					if err != nil {
						return fmt.Errorf("failed to open IPSW: %v", err)
					}
					defer zr.Close()
					if err := utils.RemoteUnzip(zr.File, patternRE, destPath, viper.GetBool("extract.flat")); err != nil {
						return fmt.Errorf("failed to extract files matching pattern: %v", err)
					}
				}
			}
		}

		return nil
	},
}
