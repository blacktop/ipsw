/*
Copyright © 2022 blacktop

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

	patchCmd.Flags().StringP("output", "o", "", "Output folder")
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

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

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

				in, err := os.CreateTemp("", "cryptex-app")
				if err != nil {
					return fmt.Errorf("failed to create temp file for cryptex-app: %v", err)
				}
				defer os.Remove(in.Name())

				f, err := zf.Open()
				if err != nil {
					return fmt.Errorf("failed to open cryptex-app: %v", err)
				}
				defer f.Close()

				io.Copy(in, f)

				dst := filepath.Join(outFolder, "AppOS", appDMG)
				os.MkdirAll(filepath.Dir(dst), 0750)
				os.Create(dst)

				log.Infof("Patching cryptex-app to %s", dst)
				if err := ridiff.RawImagePatch(in.Name(), dst); err != nil {
					return fmt.Errorf("failed to patch cryptex-app: %v", err)
				}
			}
			if regexp.MustCompile(`cryptex-system-arm64?e$`).MatchString(zf.Name) {
				systemDMG, err := i.GetSystemOsDmg()
				if err != nil {
					return fmt.Errorf("failed to get system DMG: %v", err)
				}

				in, err := os.CreateTemp("", "cryptex-system-arm64e")
				if err != nil {
					return fmt.Errorf("failed to create temp file for cryptex-system-arm64e: %v", err)
				}
				defer os.Remove(in.Name())

				f, err := zf.Open()
				if err != nil {
					return fmt.Errorf("failed to open cryptex-system-arm64e: %v", err)
				}
				defer f.Close()

				io.Copy(in, f)

				dst := filepath.Join(outFolder, "SystemOS", systemDMG)
				os.MkdirAll(filepath.Dir(dst), 0750)
				os.Create(dst)

				log.Infof("Patching cryptex-system-arm64e to %s", dst)
				if err := ridiff.RawImagePatch(in.Name(), dst); err != nil {
					return fmt.Errorf("failed to patch cryptex-system-arm64e: %v", err)
				}
			}
		}

		return nil
	},
}
