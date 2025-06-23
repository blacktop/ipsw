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
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/blacktop/lzfse-cgo"
	"github.com/dustin/go-humanize"
	"github.com/fatih/color"
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

	img4ExtractCmd.Flags().StringP("output", "o", "", "Output folder")
	img4ExtractCmd.Flags().BoolP("im4p", "p", false, "Extract IM4P payload to path")
	img4ExtractCmd.Flags().BoolP("im4m", "m", false, "Extract IM4M manifest to path")
	img4ExtractCmd.Flags().BoolP("im4r", "r", false, "Extract IM4R restore info to path")
	img4ExtractCmd.Flags().Bool("raw", false, "Extract raw IM4P data without decompression")
	img4ExtractCmd.MarkFlagDirname("output")
	img4ExtractCmd.MarkZshCompPositionalArgumentFile(1)
	viper.BindPFlag("img4.extract.output", img4ExtractCmd.Flags().Lookup("output"))
	viper.BindPFlag("img4.extract.im4p", img4ExtractCmd.Flags().Lookup("im4p"))
	viper.BindPFlag("img4.extract.im4m", img4ExtractCmd.Flags().Lookup("im4m"))
	viper.BindPFlag("img4.extract.im4r", img4ExtractCmd.Flags().Lookup("im4r"))
	viper.BindPFlag("img4.extract.raw", img4ExtractCmd.Flags().Lookup("raw"))
}

// img4ExtractCmd represents the extract command
var img4ExtractCmd = &cobra.Command{
	Use:     "extract <IMG4>",
	Aliases: []string{"e"},
	Short:   "Extract IMG4 components",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// flags
		outputDir := viper.GetString("img4.extract.output")
		im4p := viper.GetBool("img4.extract.im4p")
		im4m := viper.GetBool("img4.extract.im4m")
		im4r := viper.GetBool("img4.extract.im4r")
		rawExtract := viper.GetBool("img4.extract.raw")

		filePath := filepath.Clean(args[0])

		isImg4, err := magic.IsImg4(filePath)
		if err != nil {
			return fmt.Errorf("failed to determine file type: %v", err)
		}
		if !isImg4 {
			return fmt.Errorf("file is not an IMG4 file (for IM4P files, use 'ipsw img4 im4p extract')")
		}

		if im4p {
			if err := extractSpecificComponent(filePath, outputDir, IM4P, rawExtract); err != nil {
				return err
			}
		}
		if im4m {
			if err := extractSpecificComponent(filePath, outputDir, IM4M, rawExtract); err != nil {
				return err
			}
		}
		if im4r {
			if err := extractSpecificComponent(filePath, outputDir, IM4R, rawExtract); err != nil {
				return err
			}
		}

		return nil
	},
}

func extractSpecificComponent(filePath, outputDir string, component component, raw bool) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %v", filePath, err)
	}
	defer f.Close()

	baseName := strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filePath))

	var outFile string
	var data []byte

	if rawImg4, err := img4.ParseImg4(f); err == nil {
		switch component {
		case IM4P:
			data = rawImg4.IM4P.Raw
			outFile = fmt.Sprintf("%s.%s", baseName, IM4P)
		case IM4M:
			data = rawImg4.Manifest.FullBytes
			outFile = fmt.Sprintf("%s.%s", baseName, IM4M)
		case IM4R:
			data = rawImg4.RestoreInfo.Raw
			outFile = fmt.Sprintf("%s.%s", baseName, IM4R)
		}
	} else {
		return fmt.Errorf("failed to parse file as IMG4: %v", err)
	}

	if outputDir != "" {
		outFile = filepath.Join(outputDir, outFile)
	} else {
		outFile = filepath.Join(filepath.Dir(filePath), outFile)
	}

	// Decompress if not raw extraction and it's compressed
	if !raw && len(data) > 4 && bytes.Equal(data[:4], []byte("bvx2")) {
		utils.Indent(log.Debug, 2)("Detected LZFSE compression, decompressing...")
		if decompressed := lzfse.DecodeBuffer(data); len(decompressed) > 0 {
			data = decompressed
		}
	}

	fmt.Printf("%s             %s\n", colorField("File:"), baseName)
	fmt.Printf("%s        %s\n", colorField("Component:"), component)
	fmt.Printf("%s           %s\n", colorField("Output:"), outFile)
	fmt.Printf("%s             %s\n", colorField("Size:"), humanize.Bytes(uint64(len(data))))

	return os.WriteFile(outFile, data, 0644)
}
