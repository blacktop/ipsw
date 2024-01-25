/*
Copyright © 2024 blacktop

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
	"path/filepath"
	"regexp"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/ota/bxdiff50"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	otaPatchCmd.AddCommand(otaBxdiffCmd)

	otaBxdiffCmd.Flags().BoolP("single", "s", false, "Patch single file")
	otaBxdiffCmd.Flags().StringP("output", "o", "", "Output folder")
	otaBxdiffCmd.MarkFlagDirname("output")
	viper.BindPFlag("ota.patch.bxdiff.single", otaBxdiffCmd.Flags().Lookup("single"))
	viper.BindPFlag("ota.patch.bxdiff.output", otaBxdiffCmd.Flags().Lookup("output"))
}

// otaBxdiffCmd represents the bxdiff command
var otaBxdiffCmd = &cobra.Command{
	Use:           "bxdiff <DELTA> <TARGET>",
	Aliases:       []string{"b"},
	Short:         "Patch BXDIFF50 OTAs",
	Args:          cobra.ExactArgs(2),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		single := viper.GetBool("ota.patch.bxdiff.single")
		output := viper.GetString("ota.patch.bxdiff.output")

		if single {
			return bxdiff50.Patch(args[0], args[1], output)
		}

		panic("not implemented yet (try --single mode)")

		patchPath := filepath.Clean(args[0])

		i, err := info.Parse(patchPath)
		if err != nil {
			return fmt.Errorf("failed to parse IPSW: %v", err)
		}
		infoFolder, err := i.GetFolder()
		if err != nil {
			return fmt.Errorf("failed to get OTA folder: %v", err)
		}

		if len(output) > 0 {
			output = filepath.Join(output, infoFolder)
		} else {
			output = infoFolder
		}

		zr, err := zip.OpenReader(patchPath)
		if err != nil {
			return fmt.Errorf("failed to open OTA: %v", err)
		}
		defer zr.Close()

		var patchFiles []string
		for _, zf := range zr.File {
			if regexp.MustCompile(`AssetData/payloadv2/patches/.*$`).MatchString(zf.Name) {
				if !zf.FileInfo().IsDir() {
					patchFiles = append(patchFiles, zf.Name)
				}
			}
		}

		// FIXME: finish this

		_ = patchFiles

		return nil
	},
}
