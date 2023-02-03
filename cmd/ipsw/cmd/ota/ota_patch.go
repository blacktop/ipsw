//go:build darwin && cgo

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
package ota

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/ota/ridiff"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	OtaCmd.AddCommand(patchCmd)

	patchCmd.Flags().StringP("input", "i", "", "Input folder")
	patchCmd.Flags().StringP("output", "o", "", "Output folder")
	viper.BindPFlag("ota.patch.input", patchCmd.Flags().Lookup("input"))
	viper.BindPFlag("ota.patch.output", patchCmd.Flags().Lookup("output"))
}

// patchCmd represents the patch command
var patchCmd = &cobra.Command{
	Use:           "patch <OTA>",
	Aliases:       []string{"p"},
	Short:         "Patch cryptex files",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		patchVerbose := uint32(0)

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
			patchVerbose = 5
		}

		inFolder := viper.GetString("ota.patch.input")
		outFolder := viper.GetString("ota.patch.output")

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
			} else if regexp.MustCompile(`cryptex-system-arm64?e$`).MatchString(zf.Name) {
				systemDMG, err := i.GetSystemOsDmg()
				if err != nil {
					return fmt.Errorf("failed to get system DMG: %v", err)
				}

				pat, err := os.CreateTemp("", "cryptex-system-arm64e")
				if err != nil {
					return fmt.Errorf("failed to create temp file for cryptex-system-arm64e: %v", err)
				}
				defer os.Remove(pat.Name())

				f, err := zf.Open()
				if err != nil {
					return fmt.Errorf("failed to open cryptex-system-arm64e: %v", err)
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

				log.Infof("Patching cryptex-system-arm64e to %s", out)
				if err := ridiff.RawImagePatch(inDMG, pat.Name(), out, patchVerbose); err != nil {
					return fmt.Errorf("failed to patch cryptex-system-arm64e: %v", err)
				}
			}
		}

		return nil
	},
}
