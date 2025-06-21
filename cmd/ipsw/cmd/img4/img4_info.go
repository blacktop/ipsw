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
	"io"
	"os"
	"path/filepath"

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

func init() {
	Img4Cmd.AddCommand(img4InfoCmd)
	img4InfoCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	img4InfoCmd.MarkZshCompPositionalArgumentFile(1)

	viper.BindPFlag("img4.info.json", img4InfoCmd.Flags().Lookup("json"))
}

// img4InfoCmd represents the info command
var img4InfoCmd = &cobra.Command{
	Use:           "info <IMG4|IM4P>",
	Aliases:       []string{"i"},
	Short:         "Display IMG4/IM4P file information",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		filePath := args[0]
		jsonOutput := viper.GetBool("img4.info.json")

		f, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %v", filePath, err)
		}
		defer f.Close()

		// Try to parse as IMG4 first, then fall back to IM4P
		if img, err := img4.Parse(f); err == nil {
			return displayImg4Info(img, filePath, jsonOutput, viper.GetBool("verbose"))
		}

		// Reset file pointer and try IM4P
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("failed to reset file pointer: %v", err)
		}
		if im4p, err := img4.ParseIm4p(f); err == nil {
			return displayIm4pInfo(im4p, filePath, jsonOutput, viper.GetBool("verbose"))
		} else {
			return fmt.Errorf("failed to parse file as IMG4 or IM4P: %v", err)
		}
	},
}

func displayImg4Info(img *img4.Img4, filePath string, jsonOutput, verbose bool) error {
	if jsonOutput {
		data := map[string]any{
			"file":         filepath.Base(filePath),
			"type":         "IMG4",
			"name":         img.Name,
			"description":  img.Description,
			"manifest":     img.Manifest,
			"restore_info": img.RestoreInfo,
		}
		jsonData, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal IMG4 info: %v", err)
		}
		fmt.Println(string(jsonData))
	} else {
		fmt.Printf("%s             %s\n", colorField("File:"), filepath.Base(filePath))
		fmt.Printf("%s             IMG4\n", colorField("Type:"))
		fmt.Printf("%s             %s\n", colorField("Name:"), img.Name)
		fmt.Printf("%s      %s\n", colorField("Description:"), img.Description)

		if verbose {
			fmt.Printf("\n%s\n", colorField("Manifest Properties:"))
			for key, value := range img.Manifest.Properties {
				fmt.Printf("  %s: %v\n", colorSubField(key), value)
			}

			fmt.Printf("\n%s\n", colorField("Restore Info:"))
			fmt.Printf("  %s %x\n", colorSubField("Generator:"), img.RestoreInfo.Generator.Data)
		}
	}

	return nil
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
