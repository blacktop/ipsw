/*
Copyright © 2018-2022 blacktop

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
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/pkg/errors"
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
	extractCmd.Flags().BoolP("dmg", "m", false, "Extract File System DMG file")
	extractCmd.Flags().BoolP("iboot", "i", false, "Extract iBoot")
	extractCmd.Flags().BoolP("sep", "s", false, "Extract sep-firmware")
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
	viper.BindPFlag("extract.files", extractCmd.Flags().Lookup("files"))
	viper.BindPFlag("extract.pattern", extractCmd.Flags().Lookup("pattern"))
	viper.BindPFlag("extract.output", extractCmd.Flags().Lookup("output"))
	viper.BindPFlag("extract.flat", extractCmd.Flags().Lookup("flat"))
	viper.BindPFlag("extract.dyld-arch", extractCmd.Flags().Lookup("dyld-arch"))

	extractCmd.MarkZshCompPositionalArgumentFile(1, "*.ipsw")
	extractCmd.ValidArgsFunction = func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"ipsw", "zip"}, cobra.ShellCompDirectiveFilterFileExt
	}
}

func isURL(str string) bool {
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
}

// extractCmd represents the extract command
var extractCmd = &cobra.Command{
	Use:           "extract <IPSW/OTA | URL>",
	Short:         "Extract kernelcache, dyld_shared_cache or DeviceTree from IPSW/OTA",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		if len(viper.GetStringSlice("extract.dyld-arch")) > 0 && !viper.GetBool("extract.dyld") {
			return errors.New("--dyld-arch or -a can only be used with --dyld or -d")
		}
		if len(viper.GetStringSlice("extract.dyld-arch")) > 0 {
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

			if viper.GetBool("extract.dyld") {
				log.Error("unable to extract dyld_shared_cache remotely (try `ipsw download ota --dyld`)")
			}
			if viper.GetBool("extract.dmg") {
				log.Error("unable to extract File System DMG remotely (let the author know if this is something you want)")
			}

			// Get handle to remote ipsw zip
			zr, err := download.NewRemoteZipReader(remoteURL, &download.RemoteConfig{
				Proxy:    viper.GetString("extract.proxy"),
				Insecure: viper.GetBool("extract.insecure"),
			})
			if err != nil {
				return errors.Wrap(err, "failed to download kernelcaches from remote ipsw")
			}

			i, err := info.ParseZipFiles(zr.File)
			if err != nil {
				return fmt.Errorf("failed to parse plists in remote zip: %v", err)
			}

			destPath := filepath.Join(filepath.Clean(viper.GetString("extract.output")), i.GetFolder())

			if err := os.MkdirAll(destPath, 0750); err != nil {
				return fmt.Errorf("failed to create output directory %s: %v", destPath, err)
			}

			if viper.GetBool("extract.kernel") {
				log.Info("Extracting remote kernelcache(s)")
				err = kernelcache.RemoteParse(zr, destPath)
				if err != nil {
					return errors.Wrap(err, "failed to download kernelcaches from remote ipsw")
				}
			}

			if viper.GetBool("extract.dtree") {
				log.Info("Extracting remote DeviceTree(s)")
				if err := utils.RemoteUnzip(zr.File, regexp.MustCompile(`.*DeviceTree.*im(3|4)p$`), destPath, viper.GetBool("extract.flat")); err != nil {
					return fmt.Errorf("failed to extract DeviceTree: %v", err)
				}
			}

			if viper.GetBool("extract.iboot") {
				log.Info("Extracting remote iBoot(s)")
				if err := utils.RemoteUnzip(zr.File, regexp.MustCompile(`.*iBoot.*im4p$`), destPath, viper.GetBool("extract.flat")); err != nil {
					return fmt.Errorf("failed to extract iBoot: %v", err)
				}
			}

			if viper.GetBool("extract.sep") {
				log.Info("Extracting sep-firmware(s)")
				if err := utils.RemoteUnzip(zr.File, regexp.MustCompile(`.*sep-firmware.*im4p$`), destPath, viper.GetBool("extract.flat")); err != nil {
					return fmt.Errorf("failed to extract SEPOS: %v", err)
				}
			}

			if len(viper.GetString("extract.pattern")) > 0 {
				log.Infof("Extracting files matching pattern $#v", viper.GetString("extract.pattern"))
				validRegex, err := regexp.Compile(viper.GetString("extract.pattern"))
				if err != nil {
					return errors.Wrap(err, "failed to compile regexp")
				}
				if err := utils.RemoteUnzip(zr.File, validRegex, destPath, viper.GetBool("extract.flat")); err != nil {
					return fmt.Errorf("failed to extract files matching pattern: %v", err)
				}
			}
		} else { // local IPSW/OTA
			ipswPath := filepath.Clean(args[0])

			if _, err := os.Stat(ipswPath); os.IsNotExist(err) {
				return fmt.Errorf("file %s does not exist", ipswPath)
			}

			i, err := info.Parse(ipswPath)
			if err != nil {
				return errors.Wrap(err, "failed to parse ipsw info")
			}

			destPath := filepath.Join(filepath.Clean(viper.GetString("extract.output")), i.GetFolder())

			if err := os.MkdirAll(destPath, 0750); err != nil {
				return fmt.Errorf("failed to create output directory %s: %v", destPath, err)
			}

			if viper.GetBool("extract.kernel") {
				log.Info("Extracting kernelcaches")
				if err := kernelcache.Extract(ipswPath, destPath); err != nil {
					return errors.Wrap(err, "failed to extract kernelcaches")
				}
			}

			if viper.GetBool("extract.dyld") {
				log.Info("Extracting dyld_shared_cache")
				if err := dyld.Extract(ipswPath, destPath, viper.GetStringSlice("extract.dyld-arch")); err != nil {
					return errors.Wrap(err, "failed to extract dyld_shared_cache")
				}
			}

			if viper.GetBool("extract.dtree") {
				log.Info("Extracting DeviceTrees")
				if err := devicetree.Extract(ipswPath, destPath); err != nil {
					return errors.Wrap(err, "failed to extract DeviceTrees")
				}
			}

			if viper.GetBool("extract.dmg") {
				log.Info("Extracting File System DMG")
				if _, err := utils.Unzip(ipswPath, destPath, func(f *zip.File) bool {
					return strings.EqualFold(filepath.Base(f.Name), i.GetOsDmg())
				}); err != nil {
					return fmt.Errorf("failed extract %s from ipsw: %v", i.GetOsDmg(), err)
				}
				log.Infof("Created %s", filepath.Join(destPath, i.GetOsDmg()))
			}

			if viper.GetBool("extract.iboot") {
				log.Info("Extracting iBoot")
				if _, err := utils.Unzip(ipswPath, destPath, func(f *zip.File) bool {
					var validIBoot = regexp.MustCompile(`.*iBoot.*im4p$`)
					return validIBoot.MatchString(f.Name)
				}); err != nil {
					return errors.Wrap(err, "failed to extract iBoot from ipsw")
				}
			}

			if viper.GetBool("extract.sep") {
				log.Info("Extracting sep-firmwares")
				if _, err := utils.Unzip(ipswPath, destPath, func(f *zip.File) bool {
					var validSEP = regexp.MustCompile(`.*sep-firmware.*im4p$`)
					return validSEP.MatchString(f.Name)
				}); err != nil {
					return errors.Wrap(err, "failed to extract sep-firmware from ipsw")
				}
			}

			if len(viper.GetString("extract.pattern")) > 0 {
				log.Infof("Extracting files matching pattern %#v", viper.GetString("extract.pattern"))
				validRegex, err := regexp.Compile(viper.GetString("extract.pattern"))
				if err != nil {
					return errors.Wrap(err, "failed to compile regexp")
				}

				if viper.GetBool("extract.files") {
					dmgs, err := utils.Unzip(ipswPath, "", func(f *zip.File) bool {
						return strings.EqualFold(filepath.Base(f.Name), i.GetOsDmg())
					})
					if err != nil {
						return errors.Wrap(err, "failed extract dyld_shared_cache from ipsw")
					}
					if len(dmgs) == 0 {
						return fmt.Errorf("no OS File System .dmg found in IPSW")
					}
					defer os.Remove(dmgs[0])

					utils.Indent(log.Info, 2)(fmt.Sprintf("Mounting DMG %s", dmgs[0]))
					mountPoint, err := utils.MountFS(dmgs[0])
					if err != nil {
						return fmt.Errorf("failed to IPSW FS dmg: %v", err)
					}
					defer func() {
						utils.Indent(log.Info, 2)(fmt.Sprintf("Unmounting DMG %s", dmgs[0]))
						if err := utils.Unmount(mountPoint, false); err != nil {
							log.Errorf("failed to unmount File System DMG mount at %s: %v", dmgs[0], err)
						}
					}()
					// extract files that match regex pattern
					if err := filepath.Walk(mountPoint, func(path string, info os.FileInfo, err error) error {
						if err != nil {
							return err
						}
						if info.IsDir() {
							return nil
						}
						if validRegex.MatchString(info.Name()) {
							fname := strings.TrimPrefix(path, mountPoint)
							if err := os.MkdirAll(filepath.Join(destPath, filepath.Dir(fname)), 0750); err != nil {
								return fmt.Errorf("failed to create directory %s: %v", filepath.Join(destPath, filepath.Dir(fname)), err)
							}
							utils.Indent(log.Info, 3)(fmt.Sprintf("Extracting %s", fname))
							if err := utils.Cp(path, filepath.Join(destPath, fname)); err != nil {
								return fmt.Errorf("failed to extract %s: %v", fname, err)
							}
						}
						return nil
					}); err != nil {
						return fmt.Errorf("failed to extract File System files from IPSW: %v", err)
					}
				} else {
					zr, err := zip.OpenReader(ipswPath)
					if err != nil {
						return errors.Wrap(err, "failed to open ota zip")
					}
					defer zr.Close()
					if err := utils.RemoteUnzip(zr.File, validRegex, destPath, viper.GetBool("extract.flat")); err != nil {
						return fmt.Errorf("failed to extract files matching pattern: %v", err)
					}
				}
			}
		}

		return nil
	},
}
