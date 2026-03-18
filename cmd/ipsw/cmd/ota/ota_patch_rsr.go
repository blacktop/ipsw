//go:build darwin && cgo

/*
Copyright © 2026 blacktop

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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	otapkg "github.com/blacktop/ipsw/pkg/ota"
	"github.com/blacktop/ipsw/pkg/ota/ridiff"
	semver "github.com/hashicorp/go-version"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rsrAppCryptexRE = regexp.MustCompile(`cryptex-app$`)

func validateOTAPatchRSRArgs(cmd *cobra.Command, args []string, cryptex string) error {
	if cryptex != "" {
		if len(args) > 0 {
			return fmt.Errorf("cannot use OTA path argument with cryptex mode")
		}
		return nil
	}

	return cobra.ExactArgs(1)(cmd, args)
}

func rsrSystemCryptexRE(dyldArches []string) *regexp.Regexp {
	if len(dyldArches) == 0 {
		return regexp.MustCompile(`cryptex-system-(arm64e?|x86_64h?)$`)
	}

	patterns := make([]string, 0, len(dyldArches))
	for _, arch := range dyldArches {
		patterns = append(patterns, regexp.QuoteMeta(arch))
	}

	return regexp.MustCompile(fmt.Sprintf(`cryptex-system-(%s)$`, strings.Join(patterns, "|")))
}

func rsrCryptexType(name string, systemCryptexRE *regexp.Regexp) string {
	base := filepath.Base(name)

	switch {
	case rsrAppCryptexRE.MatchString(base):
		return "app"
	case systemCryptexRE.MatchString(base):
		return "system"
	default:
		return ""
	}
}

func rsrInputDMG(inFolder, subdir string) (string, error) {
	matches, err := filepath.Glob(filepath.Join(inFolder, subdir, "*.dmg"))
	if err != nil {
		return "", fmt.Errorf("failed to find %s dmg in input folder: %w", subdir, err)
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("failed to find %s dmg (expected 1) in input folder %s", subdir, inFolder)
	}
	if len(matches) > 1 {
		return "", fmt.Errorf("found too many %s DMGs (expected 1) in input folder %s", subdir, inFolder)
	}

	return matches[0], nil
}

func patchRSRCryptex(o *otapkg.AA, name, out, inDMG string, patchVerbose uint32) error {
	pat, err := os.CreateTemp("", filepath.Base(name)+"-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file for %s: %w", filepath.Base(name), err)
	}
	defer os.Remove(pat.Name())

	src, err := o.Open(name, false)
	if err != nil {
		_ = pat.Close()
		return fmt.Errorf("failed to open %s: %w", filepath.Base(name), err)
	}
	defer src.Close()

	if _, err := io.Copy(pat, src); err != nil {
		_ = pat.Close()
		return fmt.Errorf("failed to copy %s to temp file: %w", filepath.Base(name), err)
	}
	if err := pat.Close(); err != nil {
		return fmt.Errorf("failed to close temp file for %s: %w", filepath.Base(name), err)
	}

	if err := os.MkdirAll(filepath.Dir(out), 0o750); err != nil {
		return fmt.Errorf("failed to create output folder: %w", err)
	}

	if err := ridiff.RawImagePatch(inDMG, pat.Name(), out, patchVerbose); err != nil {
		return fmt.Errorf("failed to patch %s: %w", filepath.Base(name), err)
	}

	return nil
}

func init() {
	otaPatchCmd.AddCommand(otaPatchRsrCmd)

	otaPatchRsrCmd.Flags().StringP("cryptex", "c", "", "Cryptex file from OTA")
	otaPatchRsrCmd.Flags().StringP("input", "i", "", "Input folder")
	otaPatchRsrCmd.Flags().StringP("output", "o", "", "Output folder")
	otaPatchRsrCmd.Flags().StringArrayP("dyld-arch", "a", []string{}, "dyld_shared_cache architecture to extract")
	otaPatchRsrCmd.RegisterFlagCompletionFunc("dyld-arch", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return dyld.DscArches, cobra.ShellCompDirectiveDefault
	})
	otaPatchRsrCmd.MarkFlagDirname("input")
	otaPatchRsrCmd.MarkFlagDirname("output")
	viper.BindPFlag("ota.patch.cryptex", otaPatchRsrCmd.Flags().Lookup("cryptex"))
	viper.BindPFlag("ota.patch.input", otaPatchRsrCmd.Flags().Lookup("input"))
	viper.BindPFlag("ota.patch.output", otaPatchRsrCmd.Flags().Lookup("output"))
	viper.BindPFlag("ota.patch.dyld-arch", otaPatchRsrCmd.Flags().Lookup("dyld-arch"))
}

// otaPatchRsrCmd represents the rsr command
var otaPatchRsrCmd = &cobra.Command{
	Use:     "rsr",
	Aliases: []string{"r"},
	Short:   "Patch RSR OTAs",
	Args: func(cmd *cobra.Command, args []string) error {
		return validateOTAPatchRSRArgs(cmd, args, viper.GetString("ota.patch.cryptex"))
	},
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		patchVerbose := uint32(0)

		// flags
		cryptex := viper.GetString("ota.patch.cryptex")
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

		if len(cryptex) > 0 {
			log.Infof("Patching cryptex to %s", cryptex+".dmg")
			if err := ridiff.RawImagePatch("", cryptex, cryptex+".dmg", patchVerbose); err != nil {
				return fmt.Errorf("failed to patch %s: %v", cryptex, err)
			}
			return nil
		}

		otaPath := filepath.Clean(args[0])

		o, err := otapkg.Open(otaPath, ResolveAEAKeyFromFlags(otaPath))
		if err != nil {
			return fmt.Errorf("failed to open OTA: %w", err)
		}
		defer o.Close()

		i, err := o.Info()
		if err != nil {
			return fmt.Errorf("failed to get OTA info: %w", err)
		}
		infoFolder, err := i.GetFolder()
		if err != nil {
			return fmt.Errorf("failed to get OTA folder: %v", err)
		}

		if len(outFolder) > 0 {
			outFolder = filepath.Join(outFolder, infoFolder)
		} else {
			outFolder = infoFolder
		}

		systemCryptexRE := rsrSystemCryptexRE(dyldArches)

		for _, file := range o.Files() {
			if file.IsDir() {
				continue
			}

			switch rsrCryptexType(file.Name(), systemCryptexRE) {
			case "app":
				appDMG, err := i.GetAppOsDmg()
				if err != nil {
					return fmt.Errorf("failed to get App DMG: %v", err)
				}

				out := filepath.Join(outFolder, "AppOS", appDMG)

				var inDMG string
				if len(inFolder) > 0 {
					inDMG, err = rsrInputDMG(inFolder, "AppOS")
					if err != nil {
						return err
					}
				}

				log.Infof("Patching cryptex-app to %s", out)
				if err := patchRSRCryptex(o, file.Name(), out, inDMG, patchVerbose); err != nil {
					return err
				}
			case "system":
				systemDMG, err := i.GetSystemOsDmg()
				if err != nil {
					return fmt.Errorf("failed to get system DMG: %v", err)
				}

				out := filepath.Join(outFolder, "SystemOS", systemDMG)

				var inDMG string
				if len(inFolder) > 0 {
					inDMG, err = rsrInputDMG(inFolder, "SystemOS")
					if err != nil {
						return err
					}
				}

				log.Infof("Patching %s to %s", filepath.Base(file.Name()), out)
				if err := patchRSRCryptex(o, file.Name(), out, inDMG, patchVerbose); err != nil {
					return err
				}
			}
		}

		return nil
	},
}
