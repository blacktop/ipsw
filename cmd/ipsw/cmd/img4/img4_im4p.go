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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/blacktop/lzfse-cgo"
	"github.com/dustin/go-humanize"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	Img4Cmd.AddCommand(img4Im4pCmd)

	// Add subcommands to im4p
	img4Im4pCmd.AddCommand(img4Im4pInfoCmd)
	img4Im4pCmd.AddCommand(img4Im4pExtractCmd)
	img4Im4pCmd.AddCommand(img4Im4pCreateCmd)

	// Info command flags
	img4Im4pInfoCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	img4Im4pInfoCmd.Flags().BoolP("verbose", "v", false, "Show detailed size information")
	img4Im4pInfoCmd.MarkZshCompPositionalArgumentFile(1)

	// Extract command flags
	img4Im4pExtractCmd.Flags().StringP("output", "o", "", "Output file path")
	img4Im4pExtractCmd.MarkFlagFilename("output")
	img4Im4pExtractCmd.MarkZshCompPositionalArgumentFile(1)

	// Create command flags
	img4Im4pCreateCmd.Flags().StringP("fourcc", "f", "", "FourCC type (required)")
	img4Im4pCreateCmd.Flags().StringP("description", "d", "", "Description string")
	img4Im4pCreateCmd.Flags().StringP("output", "o", "", "Output file path")
	img4Im4pCreateCmd.Flags().Bool("compress", false, "Compress payload with LZFSE")
	img4Im4pCreateCmd.MarkFlagRequired("fourcc")
	img4Im4pCreateCmd.MarkFlagFilename("output")
	img4Im4pCreateCmd.MarkZshCompPositionalArgumentFile(1)

	viper.BindPFlag("img4.im4p.info.json", img4Im4pInfoCmd.Flags().Lookup("json"))
	viper.BindPFlag("img4.im4p.info.verbose", img4Im4pInfoCmd.Flags().Lookup("verbose"))
	viper.BindPFlag("img4.im4p.extract.output", img4Im4pExtractCmd.Flags().Lookup("output"))
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
		verboseOutput := viper.GetBool("img4.im4p.info.verbose")

		f, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %v", filePath, err)
		}
		defer f.Close()

		im4p, err := img4.ParseIm4p(f)
		if err != nil {
			return fmt.Errorf("failed to parse IM4P: %v", err)
		}

		return displayDetailedIm4pInfo(im4p, filePath, jsonOutput, verboseOutput)
	},
}

// img4Im4pExtractCmd represents the im4p extract command
var img4Im4pExtractCmd = &cobra.Command{
	Use:           "extract <IM4P>",
	Short:         "Extract IM4P payload data",
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

		if outputPath == "" {
			outputPath = filepath.Clean(filePath) + ".payload"
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

		utils.Indent(log.Info, 2)(fmt.Sprintf("Extracting payload to %s", outputPath))

		return os.WriteFile(outputPath, im4p.Data, 0644)
	},
}

func displayDetailedIm4pInfo(im4p *img4.Im4p, filePath string, jsonOutput, verbose bool) error {
	// Get file stats
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to get file stats: %v", err)
	}

	compressedSize := len(im4p.Data)
	fileSize := fileInfo.Size()

	// Try to detect compression and get uncompressed size
	compressionType := "unknown"
	var uncompressedSize int64 = -1

	if len(im4p.Data) > 0 {
		compressionType, uncompressedSize = detectCompression(im4p.Data)
	}

	if jsonOutput {
		data := map[string]interface{}{
			"file":             filepath.Base(filePath),
			"name":             im4p.Name,
			"fourcc":           im4p.Type,
			"description":      im4p.Description,
			"file_size":        fileSize,
			"compressed_size":  compressedSize,
			"compression_type": compressionType,
		}

		if verbose && uncompressedSize > 0 {
			data["uncompressed_size"] = uncompressedSize
		}

		if len(im4p.Kbags) > 0 {
			data["keybags"] = im4p.Kbags
		}

		jsonData, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal IM4P info: %v", err)
		}
		fmt.Println(string(jsonData))
	} else {
		fmt.Printf("%s             %s\n", colorField("File:"), filepath.Base(filePath))
		fmt.Printf("%s             %s\n", colorField("Name:"), im4p.Name)
		fmt.Printf("%s           %s\n", colorField("FourCC:"), im4p.Type)
		fmt.Printf("%s      %s\n", colorField("Description:"), im4p.Description)
		fmt.Printf("%s        %s\n", colorField("File Size:"), humanize.Bytes(uint64(fileSize)))
		fmt.Printf("%s  %s\n", colorField("Compressed Size:"), humanize.Bytes(uint64(compressedSize)))
		fmt.Printf("%s      %s\n", colorField("Compression:"), compressionType)

		if verbose && uncompressedSize > 0 {
			fmt.Printf("%s %s\n", colorField("Uncompressed Size:"), humanize.Bytes(uint64(uncompressedSize)))
		}

		if len(im4p.Kbags) > 0 {
			fmt.Printf("%s          %d\n", colorField("Keybags:"), len(im4p.Kbags))
			for i, kb := range im4p.Kbags {
				fmt.Printf("  [%d] %s %s\n", i, colorField("Type:"), kb.Type.String())
				if verbose {
					fmt.Printf("      %s   %x\n", colorField("IV:"), kb.IV)
					fmt.Printf("      %s  %x\n", colorField("Key:"), kb.Key)
				}
			}
		} else {
			fmt.Printf("%s          None\n", colorField("Keybags:"))
		}
	}

	return nil
}

func detectCompression(data []byte) (string, int64) {
	if len(data) < 4 {
		return "none", -1
	}

	// Check for LZFSE magic
	if bytes.Equal(data[:4], []byte("bvx2")) {
		// Try to decompress to get uncompressed size
		if decompressed := lzfse.DecodeBuffer(data); len(decompressed) > 0 {
			return "lzfse", int64(len(decompressed))
		}
		return "lzfse", -1
	}

	// Check for LZVN magic
	if len(data) >= 4 && bytes.Equal(data[:4], []byte("bvxn")) {
		// Try to decompress to get uncompressed size
		if decompressed := lzfse.DecodeBuffer(data); len(decompressed) > 0 {
			return "lzvn", int64(len(decompressed))
		}
		return "lzvn", -1
	}

	// Check for common uncompressed patterns
	// Mach-O files start with magic numbers
	if len(data) >= 4 {
		magic := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
		switch magic {
		case 0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe:
			return "none", int64(len(data))
		}
	}

	return "unknown", -1
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
		compress := viper.GetBool("img4.im4p.create.compress")

		if len(fourcc) != 4 {
			return fmt.Errorf("FourCC must be exactly 4 characters, got %d: %s", len(fourcc), fourcc)
		}

		if outputPath == "" {
			outputPath = filepath.Clean(inputPath) + ".im4p"
		}

		if description == "" {
			description = fmt.Sprintf("Generated IM4P for %s", fourcc)
		}

		return createIm4p(inputPath, outputPath, fourcc, description, compress)
	},
}

func createIm4p(inputPath, outputPath, fourcc, description string, compress bool) error {
	inputData, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %v", err)
	}

	originalSize := len(inputData)
	payloadData := inputData

	if compress {
		utils.Indent(log.Debug, 2)("Compressing payload with LZFSE...")
		compressedData := lzfse.EncodeBuffer(inputData)
		if len(compressedData) > 0 && len(compressedData) < len(inputData) {
			payloadData = compressedData
			utils.Indent(log.Debug, 2)(fmt.Sprintf("Compression: %d → %d bytes (%.1f%% reduction)",
				originalSize, len(compressedData),
				float64(originalSize-len(compressedData))/float64(originalSize)*100))
		} else {
			utils.Indent(log.Debug, 2)("Compression ineffective, using original data")
		}
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

	if compress {
		fmt.Printf("%s %s\n", colorField("Payload Size:"), humanize.Bytes(uint64(len(payloadData))))
		fmt.Printf("%s  %s\n", colorField("Compression:"), "LZFSE")
	}

	fmt.Printf("%s    %s\n", colorField("IM4P Size:"), humanize.Bytes(uint64(len(asn1Data))))

	return nil
}
