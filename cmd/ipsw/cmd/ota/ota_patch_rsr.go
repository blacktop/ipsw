//go:build darwin && cgo

/*
Copyright © 2025 blacktop

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
package ota

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/ota/ridiff"
	semver "github.com/hashicorp/go-version"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	otaPatchCmd.AddCommand(otaPatchRsrCmd)

	otaPatchRsrCmd.Flags().StringP("input", "i", "", "Input folder")
	otaPatchRsrCmd.Flags().StringP("output", "o", "", "Output folder")
	otaPatchRsrCmd.Flags().StringArrayP("dyld-arch", "a", []string{}, "dyld_shared_cache architecture to extract")
	otaPatchRsrCmd.RegisterFlagCompletionFunc("dyld-arch", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return dyld.DscArches, cobra.ShellCompDirectiveDefault
	})
	otaPatchRsrCmd.MarkFlagDirname("input")
	otaPatchRsrCmd.MarkFlagDirname("output")
	viper.BindPFlag("ota.patch.input", otaPatchRsrCmd.Flags().Lookup("input"))
	viper.BindPFlag("ota.patch.output", otaPatchRsrCmd.Flags().Lookup("output"))
	viper.BindPFlag("ota.patch.dyld-arch", otaPatchRsrCmd.Flags().Lookup("dyld-arch"))
}

// otaPatchRsrCmd represents the rsr command
var otaPatchRsrCmd = &cobra.Command{
	Use:           "rsr",
	Aliases:       []string{"r"},
	Short:         "Patch RSR OTAs",
	Args:          cobra.MinimumNArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		patchVerbose := uint32(0)

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
			patchVerbose = 5
		}

		// flags
		inFolder := viper.GetString("ota.patch.input")
		outFolder := viper.GetString("ota.patch.output")
		dyldArches := viper.GetStringSlice("ota.patch.dyld-arch")
		// validate flags
		if len(dyldArches) > 0 {
			for _, arch := range dyldArches {
				if !utils.StrSliceHas(dyld.DscArches, arch) {
					return fmt.Errorf("invalid --dyld-arch: '%s' (must be one of %s)",
						arch,
						strings.Join(dyld.DscArches, ", "))
				}
			}
		}

		// check if we are running on compatible macOS version
		host, err := utils.GetBuildInfo()
		if err != nil {
			return fmt.Errorf("failed to get host build info: %v", err)
		}
		reqVer, err := semver.NewVersion("13.0.0")
		if err != nil {
			log.Fatal("failed to convert required macOS version into semver object")
		}
		curVer, err := semver.NewVersion(host.ProductVersion)
		if err != nil {
			log.Fatal("failed to convert version into semver object")
		}
		if curVer.LessThan(reqVer) {
			return fmt.Errorf("patching OTA only supported on macOS 13+/iOS 16+ (if you are trying to run on iOS let author know as macOS is currently the only supported darwin platform)")
		}

		otaPath := filepath.Clean(args[0])

		i, err := info.Parse(otaPath)
		if err != nil {
			return fmt.Errorf("failed to parse IPSW: %v", err)
		}
		infoFolder, err := i.GetFolder()
		if err != nil {
			return fmt.Errorf("failed to get OTA folder: %v", err)
		}

		zr, err := zip.OpenReader(otaPath)
		if err != nil {
			return fmt.Errorf("failed to open OTA: %v", err)
		}
		defer zr.Close()

		if len(outFolder) > 0 {
			outFolder = filepath.Join(outFolder, infoFolder)
		} else {
			outFolder = infoFolder
		}

		for _, zf := range zr.File {
			if regexp.MustCompile(`cryptex-app$`).MatchString(zf.Name) {
				appDMG, err := i.GetAppOsDmg()
				if err != nil {
					return fmt.Errorf("failed to get App DMG: %v", err)
				}

				pat, err := os.CreateTemp("", "cryptex-app")
				if err != nil {
					return fmt.Errorf("failed to create temp file for cryptex-app: %v", err)
				}
				defer os.Remove(pat.Name())

				f, err := zf.Open()
				if err != nil {
					return fmt.Errorf("failed to open cryptex-app: %v", err)
				}
				defer f.Close()

				io.Copy(pat, f)

				out := filepath.Join(outFolder, "AppOS", appDMG)
				if err := os.MkdirAll(filepath.Dir(out), 0750); err != nil {
					return fmt.Errorf("failed to create AppOS folder: %v", err)
				}
				if _, err := os.Create(out); err != nil {
					return fmt.Errorf("failed to create AppOS dmg: %v", err)
				}

				var inDMG string
				if len(inFolder) > 0 {
					matches, err := filepath.Glob(filepath.Join(inFolder, "AppOS", "*.dmg"))
					if err != nil {
						return fmt.Errorf("failed to find AppOS dmg in input folder: %v", err)
					}
					if len(matches) == 0 {
						return fmt.Errorf("failed to find AppOS dmg (or found too many) to patch in input folder %s", inFolder)
					} else if len(matches) > 1 {
						return fmt.Errorf("found too many AppOS DMGs (expected 1) to patch in input folder %s", inFolder)
					}
					inDMG = matches[0]
				}

				log.Infof("Patching cryptex-app to %s", out)
				if err := ridiff.RawImagePatch(inDMG, pat.Name(), out, patchVerbose); err != nil {
					return fmt.Errorf("failed to patch cryptex-app: %v", err)
				}
			} else {
				re := regexp.MustCompile(`cryptex-system-(arm64e?|x86_64h?)$`)
				if len(dyldArches) > 0 {
					re = regexp.MustCompile(fmt.Sprintf(`cryptex-system-(%s)$`, strings.Join(dyldArches, "|")))
				}
				if re.MatchString(zf.Name) {
					systemDMG, err := i.GetSystemOsDmg()
					if err != nil {
						return fmt.Errorf("failed to get system DMG: %v", err)
					}

					pat, err := os.CreateTemp("", "cryptex-system")
					if err != nil {
						return fmt.Errorf("failed to create temp file for cryptex-system: %v", err)
					}
					defer os.Remove(pat.Name())

					f, err := zf.Open()
					if err != nil {
						return fmt.Errorf("failed to open cryptex-system: %v", err)
					}
					defer f.Close()

					io.Copy(pat, f)

					out := filepath.Join(outFolder, "SystemOS", systemDMG)
					if err := os.MkdirAll(filepath.Dir(out), 0750); err != nil {
						return fmt.Errorf("failed to create SystemOS folder: %v", err)
					}
					if _, err := os.Create(out); err != nil {
						return fmt.Errorf("failed to create SystemOS dmg: %v", err)
					}

					var inDMG string
					if len(inFolder) > 0 {
						matches, err := filepath.Glob(filepath.Join(inFolder, "SystemOS", "*.dmg"))
						if err != nil {
							return fmt.Errorf("failed to find SystemOS dmg in input folder: %v", err)
						}
						if len(matches) == 0 {
							return fmt.Errorf("failed to find SystemOS dmg (or found too many) to patch in input folder %s", inFolder)
						} else if len(matches) > 1 {
							return fmt.Errorf("found too many SystemOS DMGs (expected 1) to patch in input folder %s", inFolder)
						}
						inDMG = matches[0]
					}

					log.Infof("Patching %s to %s", zf.Name, out)
					if err := ridiff.RawImagePatch(inDMG, pat.Name(), out, patchVerbose); err != nil {
						return fmt.Errorf("failed to patch %s: %v", zf.Name, err)
					}
				}
			}
		}

		return nil
	},
}
