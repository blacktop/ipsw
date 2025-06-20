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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/dustin/go-humanize"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)


func init() {
	Img4Cmd.AddCommand(img4InfoCmd)
	img4InfoCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	img4InfoCmd.Flags().BoolP("verbose", "v", false, "Verbose output")
	img4InfoCmd.MarkZshCompPositionalArgumentFile(1)

	viper.BindPFlag("img4.info.json", img4InfoCmd.Flags().Lookup("json"))
	viper.BindPFlag("img4.info.verbose", img4InfoCmd.Flags().Lookup("verbose"))
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
		verboseOutput := viper.GetBool("img4.info.verbose")

		f, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %v", filePath, err)
		}
		defer f.Close()

		// Try to parse as IMG4 first, then fall back to IM4P
		if img, err := img4.Parse(f); err == nil {
			return displayImg4Info(img, filePath, jsonOutput, verboseOutput)
		}

		// Reset file pointer and try IM4P
		f.Seek(0, 0)
		if im4p, err := img4.ParseIm4p(f); err == nil {
			return displayIm4pInfo(im4p, filePath, jsonOutput, verboseOutput)
		} else {
			return fmt.Errorf("failed to parse file as IMG4 or IM4P: %v", err)
		}
	},
}

func displayImg4Info(img *img4.Img4, filePath string, jsonOutput, verbose bool) error {
	if jsonOutput {
		data := map[string]interface{}{
			"file":        filepath.Base(filePath),
			"type":        "IMG4",
			"name":        img.Name,
			"description": img.Description,
		}

		if verbose {
			data["manifest"] = img.Manifest
			data["restore_info"] = img.RestoreInfo
		}

		jsonData, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal IMG4 info: %v", err)
		}
		fmt.Println(string(jsonData))
	} else {
		fmt.Printf("%s        %s\n", colorField("File:"), filepath.Base(filePath))
		fmt.Printf("%s        IMG4\n", colorField("Type:"))
		fmt.Printf("%s        %s\n", colorField("Name:"), img.Name)
		fmt.Printf("%s %s\n", colorField("Description:"), img.Description)

		if verbose {
			fmt.Printf("\n%s\n", colorField("Manifest Properties:"))
			for key, value := range img.Manifest.Properties {
				fmt.Printf("  %s: %v\n", key, value)
			}

			fmt.Printf("\n%s\n", colorField("Restore Info:"))
			fmt.Printf("  %s %x\n", colorField("Generator:"), img.RestoreInfo.Generator.Data)
		}
	}

	return nil
}

func displayIm4pInfo(im4p *img4.Im4p, filePath string, jsonOutput, verbose bool) error {
	// Get file stats for size information
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to get file stats: %v", err)
	}

	compressedSize := len(im4p.Data)
	fileSize := fileInfo.Size()

	if jsonOutput {
		data := map[string]interface{}{
			"file":        filepath.Base(filePath),
			"type":        "IM4P",
			"name":        im4p.Name,
			"fourcc":      im4p.Type,
			"description": im4p.Description,
			"file_size":   fileSize,
		}

		if verbose {
			data["compressed_size"] = compressedSize
			data["keybags"] = im4p.Kbags
		}

		jsonData, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal IM4P info: %v", err)
		}
		fmt.Println(string(jsonData))
	} else {
		fmt.Printf("%s        %s\n", colorField("File:"), filepath.Base(filePath))
		fmt.Printf("%s        IM4P\n", colorField("Type:"))
		fmt.Printf("%s        %s\n", colorField("Name:"), im4p.Name)
		fmt.Printf("%s      %s\n", colorField("FourCC:"), im4p.Type)
		fmt.Printf("%s %s\n", colorField("Description:"), im4p.Description)
		fmt.Printf("%s   %s\n", colorField("File Size:"), humanize.Bytes(uint64(fileSize)))

		if verbose {
			fmt.Printf("%s %s\n", colorField("Compressed Size:"), humanize.Bytes(uint64(compressedSize)))
			
			if len(im4p.Kbags) > 0 {
				fmt.Printf("\n%s\n", colorField("Keybags:"))
				for i, kb := range im4p.Kbags {
					fmt.Printf("  [%d] %s %s\n", i, colorField("Type:"), kb.Type.String())
					fmt.Printf("      %s   %x\n", colorField("IV:"), kb.IV)
					fmt.Printf("      %s  %x\n", colorField("Key:"), kb.Key)
				}
			} else {
				fmt.Printf("%s     None\n", colorField("Keybags:"))
			}
		}
	}

	return nil
}