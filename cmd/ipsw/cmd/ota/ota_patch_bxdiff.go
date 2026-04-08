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
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/ota/bxdiff50"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// bxdiffPatchRE matches BXDIFF patch files in both patches/ and basesystem_patches/
// Excludes .ecc (error correction) files.
var bxdiffPatchRE = regexp.MustCompile(`AssetData/payloadv2/(patches|basesystem_patches)/[^/]+\.dmg$`)

func init() {
	otaPatchCmd.AddCommand(otaPatchBxdiffCmd)

	otaPatchBxdiffCmd.Flags().BoolP("single", "s", false, "Patch single file")
	otaPatchBxdiffCmd.Flags().StringP("input", "i", "", "Input folder containing base files to patch")
	otaPatchBxdiffCmd.Flags().StringP("output", "o", "", "Output folder")
	otaPatchBxdiffCmd.MarkFlagDirname("input")
	otaPatchBxdiffCmd.MarkFlagDirname("output")
	viper.BindPFlag("ota.patch.bxdiff.single", otaPatchBxdiffCmd.Flags().Lookup("single"))
	viper.BindPFlag("ota.patch.bxdiff.input", otaPatchBxdiffCmd.Flags().Lookup("input"))
	viper.BindPFlag("ota.patch.bxdiff.output", otaPatchBxdiffCmd.Flags().Lookup("output"))
}

// otaPatchBxdiffCmd represents the bxdiff command
var otaPatchBxdiffCmd = &cobra.Command{
	Use:           "bxdiff <OTA> | -s <DELTA> <TARGET>",
	Aliases:       []string{"b"},
	Short:         "Patch BXDIFF50 OTAs (patches and basesystem_patches)",
	SilenceErrors: true,
	Args: func(cmd *cobra.Command, args []string) error {
		if viper.GetBool("ota.patch.bxdiff.single") {
			return cobra.ExactArgs(2)(cmd, args)
		}
		return cobra.ExactArgs(1)(cmd, args)
	},
	RunE: func(cmd *cobra.Command, args []string) error {

		// flags
		single := viper.GetBool("ota.patch.bxdiff.single")
		input := viper.GetString("ota.patch.bxdiff.input")
		output := viper.GetString("ota.patch.bxdiff.output")

		if single {
			return bxdiff50.Patch(args[0], args[1], output)
		}

		patchPath := filepath.Clean(args[0])

		i, err := info.Parse(patchPath)
		if err != nil {
			return fmt.Errorf("failed to parse OTA: %v", err)
		}
		infoFolder, err := i.GetFolder()
		if err != nil {
			return fmt.Errorf("failed to get OTA folder: %v", err)
		}

		if output != "" {
			output = filepath.Join(output, infoFolder)
		} else {
			output = infoFolder
		}

		zr, err := zip.OpenReader(patchPath)
		if err != nil {
			return fmt.Errorf("failed to open OTA: %v", err)
		}
		defer zr.Close()

		patched := 0
		for _, zf := range zr.File {
			if zf.FileInfo().IsDir() {
				continue
			}
			if !bxdiffPatchRE.MatchString(zf.Name) {
				continue
			}

			patchName := filepath.Base(zf.Name)
			// Determine subdirectory from patch path (patches/ vs basesystem_patches/)
			m := bxdiffPatchRE.FindStringSubmatch(zf.Name)
			subdir := m[1] // "patches" or "basesystem_patches"

			// Extract patch from ZIP to temp
			tmpPatch, err := extractZipEntry(zf)
			if err != nil {
				return fmt.Errorf("failed to extract patch %s: %v", zf.Name, err)
			}

			outDir := filepath.Join(output, subdir)
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				os.Remove(tmpPatch)
				return fmt.Errorf("failed to create output directory: %v", err)
			}

			if input == "" {
				// No input folder — Patch() handles controlSize=0 (full replacement)
				// by decompressing the XZ stream directly. For delta patches,
				// it will fail — that's expected (need -i with base files).
				log.Infof("Processing %s/%s...", subdir, patchName)
				// Create a dummy empty target with the right name for output naming
				dummyTarget := filepath.Join(os.TempDir(), patchName)
				os.WriteFile(dummyTarget, nil, 0o644)
				if err := bxdiff50.Patch(tmpPatch, dummyTarget, outDir); err != nil {
					os.Remove(tmpPatch)
					os.Remove(dummyTarget)
					log.Errorf("failed to process %s: %v (may need -i with base files for delta patches)", patchName, err)
					continue
				}
				os.Remove(tmpPatch)
				os.Remove(dummyTarget)
				patched++
				continue
			}

			basePath := filepath.Join(input, patchName)
			if _, err := os.Stat(basePath); os.IsNotExist(err) {
				basePath = filepath.Join(input, subdir, patchName)
				if _, err := os.Stat(basePath); os.IsNotExist(err) {
					os.Remove(tmpPatch)
					log.Warnf("Skipping %s: no base file found at %s", zf.Name, patchName)
					continue
				}
			}

			log.Infof("Patching %s/%s...", subdir, patchName)
			if err := bxdiff50.Patch(tmpPatch, basePath, outDir); err != nil {
				os.Remove(tmpPatch)
				log.Errorf("failed to patch %s: %v", patchName, err)
				continue
			}
			os.Remove(tmpPatch)
			patched++
		}

		if patched == 0 {
			return fmt.Errorf("no BXDIFF patches found or applied in %s", patchPath)
		}

		log.Infof("Patched %d files to %s", patched, output)
		return nil
	},
}

// extractZipEntry extracts a ZIP entry to a temporary file and returns its path.
func extractZipEntry(zf *zip.File) (string, error) {
	rc, err := zf.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()

	tmp, err := os.CreateTemp("", "ota-bxdiff-*")
	if err != nil {
		return "", err
	}

	if _, err := io.Copy(tmp, rc); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}

	tmp.Close()
	return tmp.Name(), nil
}
