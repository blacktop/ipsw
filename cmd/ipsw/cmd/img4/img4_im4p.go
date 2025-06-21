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
	"slices"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/blacktop/lzfse-cgo"
	"github.com/blacktop/lzss"
	"github.com/dustin/go-humanize"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var compressionTypes = []string{"lzfse", "lzss", "none"}

func init() {
	Img4Cmd.AddCommand(img4Im4pCmd)

	// Add subcommands to im4p
	img4Im4pCmd.AddCommand(img4Im4pInfoCmd)
	img4Im4pCmd.AddCommand(img4Im4pExtractCmd)
	img4Im4pCmd.AddCommand(img4Im4pCreateCmd)

	// Info command flags
	img4Im4pInfoCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	img4Im4pInfoCmd.MarkZshCompPositionalArgumentFile(1)
	viper.BindPFlag("img4.im4p.info.json", img4Im4pInfoCmd.Flags().Lookup("json"))

	// Extract command flags
	img4Im4pExtractCmd.Flags().StringP("output", "o", "", "Output file path")
	img4Im4pExtractCmd.Flags().BoolP("extra", "e", false, "Extract extra data")
	img4Im4pExtractCmd.MarkFlagFilename("output")
	img4Im4pExtractCmd.MarkZshCompPositionalArgumentFile(1)
	viper.BindPFlag("img4.im4p.extract.extra", img4Im4pExtractCmd.Flags().Lookup("extra"))
	viper.BindPFlag("img4.im4p.extract.output", img4Im4pExtractCmd.Flags().Lookup("output"))

	// Create command flags
	img4Im4pCreateCmd.Flags().StringP("fourcc", "f", "", "FourCC type (required)")
	img4Im4pCreateCmd.Flags().StringP("description", "d", "", "Description string")
	img4Im4pCreateCmd.Flags().StringP("output", "o", "", "Output file path")
	img4Im4pCreateCmd.Flags().StringP("compress", "c", "none", fmt.Sprintf("Compress payload (%s)", strings.Join(compressionTypes, ", ")))
	img4Im4pCreateCmd.RegisterFlagCompletionFunc("compress", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return compressionTypes, cobra.ShellCompDirectiveDefault
	})
	img4Im4pCreateCmd.MarkFlagRequired("fourcc")
	img4Im4pCreateCmd.MarkFlagFilename("output")
	img4Im4pCreateCmd.MarkZshCompPositionalArgumentFile(1)
	viper.BindPFlag("img4.im4p.create.fourcc", img4Im4pCreateCmd.Flags().Lookup("fourcc"))
	viper.BindPFlag("img4.im4p.create.description", img4Im4pCreateCmd.Flags().Lookup("description"))
	viper.BindPFlag("img4.im4p.create.output", img4Im4pCreateCmd.Flags().Lookup("output"))
	viper.BindPFlag("img4.im4p.create.compress", img4Im4pCreateCmd.Flags().Lookup("compress"))
}

// img4Im4pCmd represents the im4p command group
var img4Im4pCmd = &cobra.Command{
	Use:   "im4p",
	Short: "IM4P payload operations",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// img4Im4pInfoCmd represents the im4p info command
var img4Im4pInfoCmd = &cobra.Command{
	Use:           "info <IM4P>",
	Short:         "Display detailed IM4P information",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		filePath := args[0]
		jsonOutput := viper.GetBool("img4.im4p.info.json")

		f, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %v", filePath, err)
		}
		defer f.Close()

		im4p, err := img4.ParseIm4p(f)
		if err != nil {
			return fmt.Errorf("failed to parse IM4P: %v", err)
		}

		return displayIm4pInfo(im4p, filePath, jsonOutput, viper.GetBool("verbose"))
	},
}

// img4Im4pExtractCmd represents the im4p extract command
var img4Im4pExtractCmd = &cobra.Command{
	Use:           "extract <IM4P>",
	Short:         "Extract IM4P data",
	Long:          "Extract IM4P payload data or extra metadata.",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		filePath := args[0]
		outputPath := viper.GetString("img4.im4p.extract.output")
		extractExtra := viper.GetBool("img4.im4p.extract.extra")

		if outputPath == "" {
			if extractExtra {
				outputPath = filepath.Clean(filePath) + ".extra"
			} else {
				outputPath = filepath.Clean(filePath) + ".payload"
			}
		}

		f, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %v", filePath, err)
		}
		defer f.Close()

		im4p, err := img4.ParseIm4p(f)
		if err != nil {
			return fmt.Errorf("failed to parse IM4P: %v", err)
		}

		if extractExtra {
			if im4p.ExtraDataSize == 0 {
				return fmt.Errorf("no extra data found in IM4P file")
			}

			utils.Indent(log.WithFields(log.Fields{
				"bytes": im4p.ExtraDataSize,
				"path":  outputPath,
			}).Info, 2)("Extracting extra data")

			extraData := im4p.GetExtraData()
			if len(extraData) == 0 {
				return fmt.Errorf("extra data is empty")
			}

			return os.WriteFile(outputPath, extraData, 0644)
		} else {
			utils.Indent(log.WithFields(log.Fields{
				"path": outputPath,
			}).Info, 2)("Extracting payload")
			// Auto-decompress if compressed
			payloadData := im4p.Data
			if compressionType, _ := detectCompression(im4p.Data); compressionType != "none" && compressionType != "unknown" {
				utils.Indent(log.Info, 3)(fmt.Sprintf("Detected %s compression, decompressing...", compressionType))
				switch compressionType {
				case "lzfse", "lzvn":
					if decompressed := lzfse.DecodeBuffer(im4p.Data); len(decompressed) > 0 {
						payloadData = decompressed
					}
				case "lzss":
					if decompressed := lzss.Decompress(im4p.Data); len(decompressed) > 0 {
						payloadData = decompressed
					}
				}
			}

			return os.WriteFile(outputPath, payloadData, 0644)
		}
	},
}

// img4Im4pCreateCmd represents the im4p create command
var img4Im4pCreateCmd = &cobra.Command{
	Use:           "create <input-file>",
	Short:         "Create IM4P payload from raw data",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		inputPath := args[0]
		fourcc := viper.GetString("img4.im4p.create.fourcc")
		description := viper.GetString("img4.im4p.create.description")
		outputPath := viper.GetString("img4.im4p.create.output")
		compressionType := viper.GetString("img4.im4p.create.compress")

		if len(fourcc) != 4 {
			return fmt.Errorf("FourCC must be exactly 4 characters, got %d: %s", len(fourcc), fourcc)
		}

		if outputPath == "" {
			outputPath = filepath.Clean(inputPath) + ".im4p"
		}

		if description == "" {
			description = fmt.Sprintf("Generated IM4P for %s", fourcc)
		}
		if compressionType == "" {
			if !slices.Contains(compressionTypes, compressionType) {
				return fmt.Errorf("unsupported compression type: %s (supported: %s)", compressionType, strings.Join(compressionTypes, ", "))
			}
		}

		return createIm4p(inputPath, outputPath, fourcc, description, compressionType)
	},
}

func createIm4p(inputPath, outputPath, fourcc, description, compressionType string) error {
	inputData, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %v", err)
	}

	originalSize := len(inputData)
	payloadData := inputData
	actualCompressionType := "none"

	// Normalize compression type input
	compressionType = strings.ToLower(strings.TrimSpace(compressionType))

	switch compressionType {
	case "lzss":
		utils.Indent(log.Debug, 2)("Compressing payload with LZSS...")
		compressedData := lzss.Compress(inputData)
		if len(compressedData) > 0 && len(compressedData) < len(inputData) {
			payloadData = compressedData
			actualCompressionType = "LZSS"
			utils.Indent(log.Debug, 2)(fmt.Sprintf("Compression: %d → %d bytes (%.1f%% reduction)",
				originalSize, len(compressedData),
				float64(originalSize-len(compressedData))/float64(originalSize)*100))
		} else {
			utils.Indent(log.Debug, 2)("LZSS compression ineffective, using original data")
		}
	case "lzfse":
		utils.Indent(log.Debug, 2)("Compressing payload with LZFSE...")
		compressedData := lzfse.EncodeBuffer(inputData)
		if len(compressedData) > 0 && len(compressedData) < len(inputData) {
			payloadData = compressedData
			actualCompressionType = "LZFSE"
			utils.Indent(log.Debug, 2)(fmt.Sprintf("Compression: %d → %d bytes (%.1f%% reduction)",
				originalSize, len(compressedData),
				float64(originalSize-len(compressedData))/float64(originalSize)*100))
		} else {
			utils.Indent(log.Debug, 2)("LZFSE compression ineffective, using original data")
		}
	case "none", "":
		// No compression
		utils.Indent(log.Debug, 2)("No compression requested")
	default:
		return fmt.Errorf("unsupported compression type: %s (supported: lzfse, lzss, none)", compressionType)
	}

	asn1Data, err := img4.CreateIm4pFile(fourcc, description, payloadData)
	if err != nil {
		return fmt.Errorf("failed to encode IM4P: %v", err)
	}

	if err := os.WriteFile(outputPath, asn1Data, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %v", err)
	}

	fmt.Printf("%s        %s\n", colorField("Input:"), filepath.Base(inputPath))
	fmt.Printf("%s       %s\n", colorField("Output:"), outputPath)
	fmt.Printf("%s       %s\n", colorField("FourCC:"), fourcc)
	fmt.Printf("%s  %s\n", colorField("Description:"), description)
	fmt.Printf("%s   %s\n", colorField("Input Size:"), humanize.Bytes(uint64(originalSize)))

	if actualCompressionType != "none" {
		fmt.Printf("%s %s\n", colorField("Payload Size:"), humanize.Bytes(uint64(len(payloadData))))
		fmt.Printf("%s  %s\n", colorField("Compression:"), actualCompressionType)
	}

	fmt.Printf("%s    %s\n", colorField("IM4P Size:"), humanize.Bytes(uint64(len(asn1Data))))

	return nil
}
