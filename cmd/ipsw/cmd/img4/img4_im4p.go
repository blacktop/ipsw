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

	// Info command flags
	img4Im4pInfoCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	img4Im4pInfoCmd.Flags().BoolP("verbose", "v", false, "Show detailed size information")
	img4Im4pInfoCmd.MarkZshCompPositionalArgumentFile(1)

	// Extract command flags
	img4Im4pExtractCmd.Flags().StringP("output", "o", "", "Output file path")
	img4Im4pExtractCmd.MarkFlagFilename("output")
	img4Im4pExtractCmd.MarkZshCompPositionalArgumentFile(1)

	viper.BindPFlag("img4.im4p.info.json", img4Im4pInfoCmd.Flags().Lookup("json"))
	viper.BindPFlag("img4.im4p.info.verbose", img4Im4pInfoCmd.Flags().Lookup("verbose"))
	viper.BindPFlag("img4.im4p.extract.output", img4Im4pExtractCmd.Flags().Lookup("output"))
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