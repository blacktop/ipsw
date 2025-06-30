/*
Copyright © 2018-2025 blacktop

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
package img4

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/dustin/go-humanize"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type component string

const (
	IM4P component = "im4p"
	IM4M component = "im4m"
	IM4R component = "im4r"
)

func init() {
	Img4Cmd.AddCommand(img4ExtractCmd)
	img4ExtractCmd.Flags().BoolP("im4p", "p", false, "Extract IM4P payload to path")
	img4ExtractCmd.Flags().BoolP("im4m", "m", false, "Extract IM4M manifest to path")
	img4ExtractCmd.Flags().BoolP("im4r", "r", false, "Extract IM4R restore info to path")
	img4ExtractCmd.Flags().Bool("raw", false, "Extract raw IM4P data without decompression")
	img4ExtractCmd.Flags().StringP("output", "o", "", "Output folder")
	img4ExtractCmd.MarkFlagDirname("output")
	img4ExtractCmd.MarkZshCompPositionalArgumentFile(1)
	viper.BindPFlag("img4.extract.im4p", img4ExtractCmd.Flags().Lookup("im4p"))
	viper.BindPFlag("img4.extract.im4m", img4ExtractCmd.Flags().Lookup("im4m"))
	viper.BindPFlag("img4.extract.im4r", img4ExtractCmd.Flags().Lookup("im4r"))
	viper.BindPFlag("img4.extract.raw", img4ExtractCmd.Flags().Lookup("raw"))
	viper.BindPFlag("img4.extract.output", img4ExtractCmd.Flags().Lookup("output"))
}

// img4ExtractCmd represents the extract command
var img4ExtractCmd = &cobra.Command{
	Use:     "extract <IMG4>",
	Aliases: []string{"e"},
	Short:   "Extract IMG4 components",
	Example: heredoc.Doc(`
		# Extract IM4P payload from IMG4 file
		❯ ipsw img4 extract --im4p kernel.img4

		# Extract manifest and restore info
		❯ ipsw img4 extract --im4m --im4r kernel.img4

		# Extract all components to a specific directory
		❯ ipsw img4 extract --im4p --im4m --im4r --output /tmp/extracted kernel.img4

		# Extract raw (compressed) IM4P data without decompression
		❯ ipsw img4 extract --im4p --raw kernel.img4`),
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// flags
		outputDir := viper.GetString("img4.extract.output")
		rawExtract := viper.GetBool("img4.extract.raw")
		// validate flags
		if rawExtract && !viper.IsSet("img4.extract.im4p") {
			return fmt.Errorf("raw extraction is only supported for IM4P payloads, please also set --im4p flag")
		}
		if !viper.IsSet("img4.extract.im4p") &&
			!viper.IsSet("img4.extract.im4m") &&
			!viper.IsSet("img4.extract.im4r") {
			return fmt.Errorf("at least one extraction flag must be set (--im4p, --im4m, --im4r)")
		}

		filePath := filepath.Clean(args[0])

		isImg4, err := magic.IsImg4(filePath)
		if err != nil {
			return fmt.Errorf("failed to determine file type: %v", err)
		}
		if !isImg4 {
			return fmt.Errorf("file is not an IMG4 file (for IM4P files, use 'ipsw img4 im4p extract')")
		}

		img, err := img4.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to parse IMG4 file: %v", err)
		}

		components := []struct {
			name      component
			enabled   bool
			extractor func(*img4.Image) []byte
		}{
			{IM4P, viper.GetBool("img4.extract.im4p"), func(i *img4.Image) []byte {
				if i.Payload != nil {
					if rawExtract {
						return i.Payload.Data
					}
					return i.Payload.Raw
				}
				return nil
			}},
			{IM4M, viper.GetBool("img4.extract.im4m"), func(i *img4.Image) []byte {
				if i.Manifest != nil {
					return i.Manifest.Raw
				}
				return nil
			}},
			{IM4R, viper.GetBool("img4.extract.im4r"), func(i *img4.Image) []byte {
				if i.RestoreInfo != nil {
					return i.RestoreInfo.Raw
				}
				return nil
			}},
		}

		baseName := strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filePath))

		for _, c := range components {
			if c.enabled {
				data := c.extractor(img)
				if data == nil {
					log.Warnf("component %s not found in IMG4", c.name)
					continue
				}

				outFile := fmt.Sprintf("%s.%s", baseName, c.name)

				var raw string
				if rawExtract {
					outFile += ".raw" // Append .raw for raw extraction
					raw = "RAW "
				}

				if outputDir != "" {
					outFile = filepath.Join(outputDir, outFile)
				} else {
					// Default to same directory as the input file
					outFile = filepath.Join(filepath.Dir(filePath), outFile)
				}

				if err := os.MkdirAll(filepath.Dir(outFile), 0755); err != nil {
					return fmt.Errorf("failed to create output directory for component %s: %v", c.name, err)
				}

				log.WithFields(log.Fields{
					"component": c.name,
					"path":      outFile,
					"size":      humanize.Bytes(uint64(len(data))),
				}).Infof("Extracting %sIMG4 Component", raw)

				if err := os.WriteFile(outFile, data, 0644); err != nil {
					return fmt.Errorf("failed to write component %s: %v", c.name, err)
				}
			}
		}

		return nil
	},
}
