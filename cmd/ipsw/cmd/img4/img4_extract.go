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
	"slices"
	"strings"

	"github.com/apex/log"
	icmd "github.com/blacktop/ipsw/internal/commands/img4"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/blacktop/lzfse-cgo"
	"github.com/dustin/go-humanize"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var components = []string{"payload", "manifest", "restore-info"}

func init() {
	Img4Cmd.AddCommand(img4ExtractCmd)

	img4ExtractCmd.Flags().Bool("img4", false, "Input file is an IMG4")
	img4ExtractCmd.Flags().StringP("output", "o", "", "Output folder")
	img4ExtractCmd.Flags().String("component", "", "Extract specific component (payload, manifest, restore-info)")
	img4ExtractCmd.RegisterFlagCompletionFunc("component", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return components, cobra.ShellCompDirectiveDefault
	})
	img4ExtractCmd.Flags().Bool("raw", false, "Extract raw data without decompression")
	img4ExtractCmd.MarkFlagDirname("output")
	viper.BindPFlag("img4.extract.img4", img4ExtractCmd.Flags().Lookup("img4"))
	viper.BindPFlag("img4.extract.output", img4ExtractCmd.Flags().Lookup("output"))
	viper.BindPFlag("img4.extract.component", img4ExtractCmd.Flags().Lookup("component"))
	viper.BindPFlag("img4.extract.raw", img4ExtractCmd.Flags().Lookup("raw"))
	img4ExtractCmd.MarkZshCompPositionalArgumentFile(1)
}

// img4ExtractCmd represents the extract command
var img4ExtractCmd = &cobra.Command{
	Use:     "extract <IMG4|IM4P>",
	Aliases: []string{"e"},
	Short:   "Extract IMG4/IM4P components",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// flags
		isImg4 := viper.GetBool("img4.extract.img4")
		outputDir := viper.GetString("img4.extract.output")
		component := viper.GetString("img4.extract.component")
		rawExtract := viper.GetBool("img4.extract.raw")

		filePath := filepath.Clean(args[0])

		// Handle component-specific extraction
		if component != "" {
			if !slices.Contains(components, component) {
				return fmt.Errorf("invalid component '%s'. Valid options: %s", component, strings.Join(components, ", "))
			}
			return extractSpecificComponent(filePath, outputDir, component, rawExtract)
		}

		// Default behavior - extract payload
		outFile := filePath + ".payload"
		if outputDir != "" {
			if filepath.Ext(outputDir) != "" {
				outFile = outputDir
			} else {
				outFile = filepath.Join(outputDir, filepath.Base(outFile))
			}
		}

		utils.Indent(log.Info, 2)(fmt.Sprintf("Extracting payload to file %s", outFile))

		if rawExtract {
			return extractRawPayload(filePath, outFile, isImg4)
		}

		return icmd.ExtractPayload(filePath, outFile, isImg4)
	},
}

func extractSpecificComponent(filePath, outputDir, component string, raw bool) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %v", filePath, err)
	}
	defer f.Close()

	baseName := filepath.Base(filePath)
	var outFile string
	var data []byte

	// Try to parse as IMG4 first
	if rawImg4, err := img4.ParseImg4(f); err == nil {
		switch component {
		case "payload":
			data = rawImg4.IM4P.Data
			outFile = baseName + ".payload"
		case "manifest":
			data = rawImg4.Manifest.Bytes
			outFile = baseName + ".im4m"
		case "restore-info":
			data = rawImg4.RestoreInfo.Generator.Bytes
			outFile = baseName + ".im4r"
		default:
			return fmt.Errorf("invalid component '%s'. Valid options: payload, manifest, restore-info", component)
		}
	} else {
		// Fall back to IM4P
		f.Seek(0, 0)
		if im4p, err := img4.ParseIm4p(f); err == nil {
			if component != "payload" {
				return fmt.Errorf("component '%s' not available in IM4P files. Only 'payload' is supported", component)
			}
			data = im4p.Data
			outFile = baseName + ".payload"
		} else {
			return fmt.Errorf("failed to parse file as IMG4 or IM4P: %v", err)
		}
	}

	if outputDir != "" {
		// Check if outputDir is a file path or directory
		if filepath.Ext(outputDir) != "" {
			outFile = outputDir
		} else {
			outFile = filepath.Join(outputDir, outFile)
		}
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

func extractRawPayload(filePath, outFile string, isImg4 bool) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer f.Close()

	var data []byte

	if isImg4 {
		i, err := img4.ParseImg4(f)
		if err != nil {
			return fmt.Errorf("failed to parse IMG4: %v", err)
		}
		data = i.IM4P.Data
	} else {
		i, err := img4.ParseIm4p(f)
		if err != nil {
			return fmt.Errorf("failed to parse IM4P: %v", err)
		}
		data = i.Data
	}

	fmt.Printf("%s             %s\n", colorField("File:"), filepath.Base(filePath))
	fmt.Printf("%s           %s\n", colorField("Output:"), outFile)
	fmt.Printf("%s             %s\n", colorField("Size:"), humanize.Bytes(uint64(len(data))))

	return os.WriteFile(outFile, data, 0644)
}
