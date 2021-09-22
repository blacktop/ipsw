/*
Copyright © 2019 blacktop

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
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"path"
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
)

func init() {
	rootCmd.AddCommand(extractCmd)

	extractCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	extractCmd.Flags().Bool("insecure", false, "do not verify ssl certs")

	extractCmd.Flags().BoolP("remote", "r", false, "Extract from URL")
	extractCmd.Flags().BoolP("kernel", "k", false, "Extract kernelcache")
	extractCmd.Flags().BoolP("dyld", "d", false, "Extract dyld_shared_cache")
	extractCmd.Flags().BoolP("dtree", "t", false, "Extract DeviceTree")
	extractCmd.Flags().BoolP("dmg", "f", false, "Extract File System DMG")
	extractCmd.Flags().BoolP("iboot", "i", false, "Extract iBoot")
	extractCmd.Flags().BoolP("sep", "s", false, "Extract sep-firmware")

	extractCmd.MarkZshCompPositionalArgumentFile(1, "*.ipsw")
}

func isURL(str string) bool {
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
}

// extractCmd represents the extract command
var extractCmd = &cobra.Command{
	Use:   "extract <IPSW | URL> <DEST>",
	Short: "Extract kernelcache, dyld_shared_cache or DeviceTree from IPSW",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		kernelFlag, _ := cmd.Flags().GetBool("kernel")
		dyldFlag, _ := cmd.Flags().GetBool("dyld")
		deviceTreeFlag, _ := cmd.Flags().GetBool("dtree")
		dmgFlag, _ := cmd.Flags().GetBool("dmg")
		ibootFlag, _ := cmd.Flags().GetBool("iboot")
		sepFlag, _ := cmd.Flags().GetBool("sep")
		remote, _ := cmd.Flags().GetBool("remote")

		var destPath string
		if len(args) > 1 {
			destPath = filepath.Clean(args[1])
		}

		if remote {
			proxy, _ := cmd.Flags().GetString("proxy")
			insecure, _ := cmd.Flags().GetBool("insecure")

			if !isURL(args[0]) {
				log.Fatal("must supply valid URL when using the remote flag")
			}

			if deviceTreeFlag {
				log.Error("unable to extract DeviceTree remotely (for now)")
				// err := devicetree.RemoteParse(args[0])
				// if err != nil {
				// 	return errors.Wrap(err, "failed to extract DeviceTree")
				// }
			}
			if dyldFlag {
				log.Error("unable to extract dyld_shared_cache remotely (try download ota)")
			}
			// Get handle to remote ipsw zip
			zr, err := download.NewRemoteZipReader(args[0], &download.RemoteConfig{
				Proxy:    proxy,
				Insecure: insecure,
			})
			if err != nil {
				return errors.Wrap(err, "failed to download kernelcaches from remote ipsw")
			}

			if dmgFlag {
				log.Error("unable to extract File System DMG remotely (let the author know if this is something you want)")
			}

			if kernelFlag {
				log.Info("Extracting Kernelcache")
				err = kernelcache.RemoteParse(zr, destPath)
				if err != nil {
					return errors.Wrap(err, "failed to download kernelcaches from remote ipsw")
				}
			}

			if ibootFlag {
				log.Info("Extracting Remote iBoot(s)")
				ipsw, err := info.ParseZipFiles(zr.File)
				if err != nil {
					return errors.Wrap(err, "failed to download iBoot(s) from remote ipsw")
				}
				var validIBoot = regexp.MustCompile(`.*iBoot.*im4p$`)
				for _, f := range zr.File {
					if validIBoot.MatchString(f.Name) {
						folder := ipsw.GetFolderForFile(path.Base(f.Name))
						os.Mkdir(folder, os.ModePerm)
						if _, err := os.Stat(filepath.Join(folder, filepath.Base(f.Name))); os.IsNotExist(err) {
							data := make([]byte, f.UncompressedSize64)
							rc, err := f.Open()
							if err != nil {
								return errors.Wrapf(err, "failed to open file in remote ipsw: %s", f.Name)
							}
							io.ReadFull(rc, data)
							rc.Close()

							err = ioutil.WriteFile(filepath.Join(folder, filepath.Base(f.Name)), data, 0644)
							if err != nil {
								return errors.Wrapf(err, "failed to write %s", f.Name)
							}
						} else {
							log.Warnf("%s already exists", filepath.Join(folder, filepath.Base(f.Name)))
						}
					}
				}
			}

			if sepFlag {
				log.Info("Extracting sep-firmwares")
				ipsw, err := info.ParseZipFiles(zr.File)
				if err != nil {
					return errors.Wrap(err, "failed to download sep-firmwares from remote ipsw")
				}
				var validSEP = regexp.MustCompile(`.*sep-firmware.*im4p$`)
				for _, f := range zr.File {
					if validSEP.MatchString(f.Name) {
						folder := ipsw.GetFolderForFile(path.Base(f.Name))
						os.Mkdir(folder, os.ModePerm)
						if _, err := os.Stat(filepath.Join(folder, filepath.Base(f.Name))); os.IsNotExist(err) {
							data := make([]byte, f.UncompressedSize64)
							rc, err := f.Open()
							if err != nil {
								return errors.Wrapf(err, "failed to open file in remote ipsw: %s", f.Name)
							}
							io.ReadFull(rc, data)
							rc.Close()

							err = ioutil.WriteFile(filepath.Join(folder, filepath.Base(f.Name)), data, 0644)
							if err != nil {
								return errors.Wrapf(err, "failed to write %s", f.Name)
							}
						} else {
							log.Warnf("%s already exists", filepath.Join(folder, filepath.Base(f.Name)))
						}
					}
				}
			}

		} else {

			ipswPath := filepath.Clean(args[0])

			if _, err := os.Stat(ipswPath); os.IsNotExist(err) {
				return fmt.Errorf("file %s does not exist", ipswPath)
			}

			if kernelFlag {
				log.Info("Extracting kernelcaches")
				err := kernelcache.Extract(ipswPath, destPath)
				if err != nil {
					return errors.Wrap(err, "failed to extract kernelcaches")
				}
			}

			if dyldFlag {
				log.Info("Extracting dyld_shared_cache")
				err := dyld.Extract(ipswPath, destPath)
				if err != nil {
					return errors.Wrap(err, "failed to extract dyld_shared_cache")
				}
			}

			if deviceTreeFlag {
				log.Info("Extracting DeviceTrees")
				err := devicetree.Extract(ipswPath, destPath)
				if err != nil {
					return errors.Wrap(err, "failed to extract DeviceTrees")
				}
			}

			if dmgFlag {
				log.Info("Extracting File System DMG")
				i, err := info.Parse(ipswPath)
				if err != nil {
					return errors.Wrap(err, "failed to parse ipsw info")
				}
				_, err = utils.Unzip(ipswPath, destPath, func(f *zip.File) bool {
					if strings.EqualFold(filepath.Base(f.Name), i.GetOsDmg()) {
						return true
					}
					return false
				})
				if err != nil {
					return fmt.Errorf("failed extract %s from ipsw: %v", i.GetOsDmg(), err)
				}
				log.Infof("Created %s", filepath.Join(destPath, i.GetOsDmg()))
			}

			if ibootFlag {
				log.Info("Extracting iBoot")
				_, err := utils.Unzip(ipswPath, "", func(f *zip.File) bool {
					var validIBoot = regexp.MustCompile(`.*iBoot.*im4p$`)
					return validIBoot.MatchString(f.Name)
				})

				if err != nil {
					return errors.Wrap(err, "failed to extract iBoot from ipsw")
				}
			}

			if sepFlag {
				log.Info("Extracting sep-firmwares")
				_, err := utils.Unzip(ipswPath, "", func(f *zip.File) bool {
					var validSEP = regexp.MustCompile(`.*sep-firmware.*im4p$`)
					return validSEP.MatchString(f.Name)
				})

				if err != nil {
					return errors.Wrap(err, "failed to extract sep-firmware from ipsw")
				}
			}
		}

		return nil
	},
}
