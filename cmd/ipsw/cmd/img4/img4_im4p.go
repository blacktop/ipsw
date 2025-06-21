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
	"crypto/aes"
	"encoding/hex"
	"encoding/json"
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
	img4Im4pExtractCmd.Flags().BoolP("kbag", "b", false, "Extract keybags")
	img4Im4pExtractCmd.Flags().BoolP("json", "j", false, "Output keybags as JSON")
	img4Im4pExtractCmd.Flags().String("iv-key", "", "AES iv+key for decryption")
	img4Im4pExtractCmd.Flags().StringP("iv", "i", "", "AES iv for decryption")
	img4Im4pExtractCmd.Flags().StringP("key", "k", "", "AES key for decryption")
	img4Im4pExtractCmd.MarkFlagFilename("output")
	img4Im4pExtractCmd.MarkZshCompPositionalArgumentFile(1)
	viper.BindPFlag("img4.im4p.extract.extra", img4Im4pExtractCmd.Flags().Lookup("extra"))
	viper.BindPFlag("img4.im4p.extract.kbag", img4Im4pExtractCmd.Flags().Lookup("kbag"))
	viper.BindPFlag("img4.im4p.extract.json", img4Im4pExtractCmd.Flags().Lookup("json"))
	viper.BindPFlag("img4.im4p.extract.output", img4Im4pExtractCmd.Flags().Lookup("output"))
	viper.BindPFlag("img4.im4p.extract.iv-key", img4Im4pExtractCmd.Flags().Lookup("iv-key"))
	viper.BindPFlag("img4.im4p.extract.iv", img4Im4pExtractCmd.Flags().Lookup("iv"))
	viper.BindPFlag("img4.im4p.extract.key", img4Im4pExtractCmd.Flags().Lookup("key"))

	// Create command flags
	img4Im4pCreateCmd.Flags().StringP("fourcc", "f", "", "FourCC type (required)")
	img4Im4pCreateCmd.Flags().StringP("description", "d", "", "Description string")
	img4Im4pCreateCmd.Flags().StringP("output", "o", "", "Output file path")
	img4Im4pCreateCmd.Flags().StringP("compress", "c", "none", fmt.Sprintf("Compress payload (%s)", strings.Join(compressionTypes, ", ")))
	img4Im4pCreateCmd.Flags().StringP("extra", "e", "", "Extra data file to append")
	img4Im4pCreateCmd.RegisterFlagCompletionFunc("compress", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return compressionTypes, cobra.ShellCompDirectiveDefault
	})
	img4Im4pCreateCmd.MarkFlagRequired("fourcc")
	img4Im4pCreateCmd.MarkFlagFilename("output")
	img4Im4pCreateCmd.MarkFlagFilename("extra")
	img4Im4pCreateCmd.MarkZshCompPositionalArgumentFile(1)
	viper.BindPFlag("img4.im4p.create.fourcc", img4Im4pCreateCmd.Flags().Lookup("fourcc"))
	viper.BindPFlag("img4.im4p.create.description", img4Im4pCreateCmd.Flags().Lookup("description"))
	viper.BindPFlag("img4.im4p.create.output", img4Im4pCreateCmd.Flags().Lookup("output"))
	viper.BindPFlag("img4.im4p.create.compress", img4Im4pCreateCmd.Flags().Lookup("compress"))
	viper.BindPFlag("img4.im4p.create.extra", img4Im4pCreateCmd.Flags().Lookup("extra"))
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

func displayIm4pInfo(im4p *img4.Im4p, filePath string, jsonOutput, verbose bool) error {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to get file stats: %v", err)
	}
	fileSize := fileInfo.Size()
	dataSize := len(im4p.Data)
	encrypted := len(im4p.Kbags) > 0

	// Try to detect compression and get uncompressed size
	compressionType := "unknown"
	var uncompressedSize int64 = -1

	if dataSize > 0 {
		compressionType, uncompressedSize = detectCompression(im4p.Data)
	}

	if jsonOutput {
		data := map[string]any{
			"file":             filepath.Base(filePath),
			"name":             im4p.Name,
			"fourcc":           im4p.Type,
			"description":      im4p.Description,
			"file_size":        fileSize,
			"data_size":        dataSize,
			"compression_type": compressionType,
			"encrypted":        encrypted,
			"keybags":          im4p.Kbags,
		}
		if uncompressedSize > 0 {
			data["uncompressed_size"] = uncompressedSize
		}
		if im4p.ExtraDataSize > 0 {
			data["extra_data_size"] = im4p.ExtraDataSize
		}
		if len(im4p.Properties) > 0 {
			data["properties"] = im4p.Properties
		}
		jsonData, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal IM4P info: %v", err)
		}
		fmt.Println(string(jsonData))
	} else {
		fmt.Printf("%s               %s\n", colorField("File:"), filepath.Base(filePath))
		fmt.Printf("%s               %s\n", colorField("Name:"), im4p.Name)
		fmt.Printf("%s             %s\n", colorField("FourCC:"), im4p.Type)
		fmt.Printf("%s        %s\n", colorField("Description:"), im4p.Description)
		fmt.Printf("%s          %s (%d bytes)\n", colorField("File Size:"), humanize.Bytes(uint64(fileSize)), fileSize)
		fmt.Printf("%s          %s (%d bytes)\n", colorField("Data Size:"), humanize.Bytes(uint64(dataSize)), dataSize)
		if len(im4p.Kbags) == 0 {
			fmt.Printf("%s        %s\n", colorField("Compression:"), compressionType)
		}

		if uncompressedSize > 0 {
			fmt.Printf("%s  %s (%d bytes)\n", colorField("Uncompressed Size:"), humanize.Bytes(uint64(uncompressedSize)), uncompressedSize)
		}

		if len(im4p.Kbags) > 0 {
			fmt.Printf("%s          %t\n", colorField("Encrypted:"), encrypted)
			fmt.Printf("%s\n", colorField("Keybags:"))
			for i, kb := range im4p.Kbags {
				fmt.Printf("  [%d] %s %s\n", i, colorField("Type:"), kb.Type.String())
				fmt.Printf("      %s   %x\n", colorField("IV:"), kb.IV)
				fmt.Printf("      %s  %x\n", colorField("Key:"), kb.Key)
			}
		}

		if len(im4p.Properties) > 0 {
			fmt.Printf("%s\n", colorField("Properties:"))
			for key, value := range im4p.Properties {
				switch v := value.(type) {
				case int64, uint64:
					fmt.Printf("    %s: %#x\n", colorSubField(key), v)
				case string:
					fmt.Printf("    %s: %s\n", colorSubField(key), v)
				case []byte:
					if verbose {
						fmt.Printf("    %s:\n%s\n", colorSubField(key), utils.HexDump(v, 0))
					} else {
						if len(v) > 15 {
							fmt.Printf("    %s: %v (length: %d)\n", colorSubField(key), v[0:15], len(v))
						} else {
							fmt.Printf("    %s: %v\n", colorSubField(key), v)
						}
					}
				default:
					fmt.Printf("    %s: %v\n", colorSubField(key), v)
				}
			}
		}

		if im4p.ExtraDataSize > 0 {
			fmt.Printf("%s    %s (%d bytes)\n", colorField("Extra Data Size:"), humanize.Bytes(uint64(im4p.ExtraDataSize)), im4p.ExtraDataSize)
			if verbose {
				fmt.Printf("%s\n%s\n", colorField("Extra Data:"), utils.HexDump(im4p.GetExtraData(), 0))
			}
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

	// Check for LZSS compression (complzss magic)
	if len(data) >= 8 && bytes.Equal(data[:8], []byte("complzss")) {
		// Try to decompress to get uncompressed size
		if decompressed := lzss.Decompress(data); len(decompressed) > 0 {
			return "lzss", int64(len(decompressed))
		}
		return "lzss", -1
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

		filePath := filepath.Clean(args[0])
		// flags
		outputPath := viper.GetString("img4.im4p.extract.output")
		extractExtra := viper.GetBool("img4.im4p.extract.extra")
		extractKbag := viper.GetBool("img4.im4p.extract.kbag")
		asJSON := viper.GetBool("img4.im4p.extract.json")
		ivkeyStr := viper.GetString("img4.im4p.extract.iv-key")
		ivStr := viper.GetString("img4.im4p.extract.iv")
		keyStr := viper.GetString("img4.im4p.extract.key")
		// validate flags
		if extractExtra && extractKbag {
			return fmt.Errorf("cannot specify both --extra and --kbag")
		}
		if extractKbag && !asJSON && len(outputPath) > 0 {
			return fmt.Errorf("cannot specify --output with --kbag when not using --json")
		}
		// Check if decryption is requested
		needsDecryption := len(ivkeyStr) != 0 || len(ivStr) != 0 || len(keyStr) != 0
		if needsDecryption {
			if extractExtra {
				return fmt.Errorf("cannot decrypt extra data, only payload can be decrypted")
			}
			if len(ivkeyStr) != 0 && (len(ivStr) != 0 || len(keyStr) != 0) {
				return fmt.Errorf("cannot specify both --iv-key AND --iv/--key")
			} else if len(ivkeyStr) == 0 && (len(ivStr) == 0 || len(keyStr) == 0) {
				return fmt.Errorf("must specify either --iv-key OR --iv/--key")
			}
		}

		if outputPath == "" {
			if extractExtra {
				outputPath = filepath.Clean(filePath) + ".extra"
			} else if needsDecryption {
				outputPath = filepath.Clean(filePath) + ".dec"
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

		if extractKbag {
			if len(im4p.Kbags) == 0 {
				return fmt.Errorf("no keybags found in IM4P")
			}
			if asJSON {
				dat, err := json.Marshal(&struct {
					Name        string        `json:"name,omitempty"`
					Description string        `json:"description,omitempty"`
					Keybags     []img4.Keybag `json:"keybags,omitempty"`
				}{
					Name:        filepath.Base(args[0]),
					Description: im4p.Description,
					Keybags:     im4p.Kbags,
				})
				if err != nil {
					return fmt.Errorf("failed to marshal im4g kbag: %v", err)
				}
				if viper.IsSet("img4.im4p.extract.output") {
					utils.Indent(log.WithFields(log.Fields{
						"path": outputPath,
					}).Info, 2)("Writing keybags JSON to file")
					return os.WriteFile(outputPath, dat, 0644)
				} else {
					fmt.Println(string(dat))
				}
			} else {
				fmt.Println("Keybags:")
				for _, kb := range im4p.Kbags {
					fmt.Println(kb)
				}
			}
			return nil
		}

		// Handle decryption if requested
		if needsDecryption {
			if !im4p.Encrypted {
				return fmt.Errorf("cannot decrypt unencrypted IM4P")
			}

			var iv []byte
			var key []byte

			if len(ivkeyStr) != 0 {
				ivkey, err := hex.DecodeString(ivkeyStr)
				if err != nil {
					return fmt.Errorf("failed to decode --iv-key: %v", err)
				}
				iv = ivkey[:aes.BlockSize]
				key = ivkey[aes.BlockSize:]
			} else {
				var err error
				iv, err = hex.DecodeString(ivStr)
				if err != nil {
					return fmt.Errorf("failed to decode --iv: %v", err)
				}
				key, err = hex.DecodeString(keyStr)
				if err != nil {
					return fmt.Errorf("failed to decode --key: %v", err)
				}
			}
			utils.Indent(log.WithFields(log.Fields{
				"path": outputPath,
			}).Info, 2)("Decrypting Payload")
			return img4.DecryptPayload(filePath, outputPath, iv, key)
		}

		if extractExtra {
			if im4p.Encrypted {
				log.Warn("extracting encrypted IM4P extra data")
			}
			if im4p.ExtraDataSize == 0 {
				return fmt.Errorf("no extra data found in IM4P file")
			}

			utils.Indent(log.WithFields(log.Fields{
				"bytes": im4p.ExtraDataSize,
				"path":  outputPath,
			}).Info, 2)("Extracting Extra Data")

			extraData := im4p.GetExtraData()
			if len(extraData) == 0 {
				return fmt.Errorf("extra data is empty")
			}

			return os.WriteFile(outputPath, extraData, 0644)
		}

		utils.Indent(log.WithFields(log.Fields{
			"path": outputPath,
		}).Info, 2)("Extracting Payload")
		if im4p.Encrypted {
			utils.Indent(log.Warn, 3)("extracting encrypted IM4P payload")
		}
		payloadData := im4p.Data
		if compressionType, _ := detectCompression(im4p.Data); compressionType != "none" && compressionType != "unknown" {
			utils.Indent(log.WithFields(log.Fields{
				"type": compressionType,
				"size": len(im4p.Data),
			}).Info, 3)("Decompressing payload")
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
		extraPath := viper.GetString("img4.im4p.create.extra")

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

		return createIm4p(inputPath, outputPath, fourcc, description, compressionType, extraPath)
	},
}

func createIm4p(inputPath, outputPath, fourcc, description, compressionType, extraPath string) error {
	inputData, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %v", err)
	}

	var extraData []byte
	if extraPath != "" {
		extraData, err = os.ReadFile(extraPath)
		if err != nil {
			return fmt.Errorf("failed to read extra data file: %v", err)
		}
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

	asn1Data, err := img4.CreateIm4pFileWithExtra(fourcc, description, payloadData, extraData)
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

	if len(extraData) > 0 {
		fmt.Printf("%s   %s (%s)\n", colorField("Extra Data:"), filepath.Base(extraPath), humanize.Bytes(uint64(len(extraData))))
	}

	if actualCompressionType != "none" {
		fmt.Printf("%s %s\n", colorField("Payload Size:"), humanize.Bytes(uint64(len(payloadData))))
		fmt.Printf("%s  %s\n", colorField("Compression:"), actualCompressionType)
	}

	fmt.Printf("%s    %s\n", colorField("IM4P Size:"), humanize.Bytes(uint64(len(asn1Data))))

	return nil
}
