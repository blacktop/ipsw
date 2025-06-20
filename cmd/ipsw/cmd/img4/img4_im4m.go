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
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/dustin/go-humanize"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	Img4Cmd.AddCommand(img4Im4mCmd)

	// Add subcommands to im4m
	img4Im4mCmd.AddCommand(img4Im4mInfoCmd)
	img4Im4mCmd.AddCommand(img4Im4mExtractCmd)

	// Info command flags
	img4Im4mInfoCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	img4Im4mInfoCmd.Flags().BoolP("verbose", "v", false, "Show detailed information")
	img4Im4mInfoCmd.MarkZshCompPositionalArgumentFile(1)

	// Extract command flags
	img4Im4mExtractCmd.Flags().StringP("output", "o", "", "Output file path")
	img4Im4mExtractCmd.Flags().Bool("shsh", false, "Extract from SHSH blob")
	img4Im4mExtractCmd.MarkFlagFilename("output")
	img4Im4mExtractCmd.MarkZshCompPositionalArgumentFile(1)

	viper.BindPFlag("img4.im4m.info.json", img4Im4mInfoCmd.Flags().Lookup("json"))
	viper.BindPFlag("img4.im4m.info.verbose", img4Im4mInfoCmd.Flags().Lookup("verbose"))
	viper.BindPFlag("img4.im4m.extract.output", img4Im4mExtractCmd.Flags().Lookup("output"))
	viper.BindPFlag("img4.im4m.extract.shsh", img4Im4mExtractCmd.Flags().Lookup("shsh"))
}

// img4Im4mCmd represents the im4m command group
var img4Im4mCmd = &cobra.Command{
	Use:   "im4m",
	Short: "IM4M manifest operations",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// img4Im4mInfoCmd represents the im4m info command
var img4Im4mInfoCmd = &cobra.Command{
	Use:           "info <IMG4>",
	Short:         "Display IM4M manifest information",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		filePath := args[0]
		jsonOutput := viper.GetBool("img4.im4m.info.json")
		verboseOutput := viper.GetBool("img4.im4m.info.verbose")

		f, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %v", filePath, err)
		}
		defer f.Close()

		img, err := img4.Parse(f)
		if err != nil {
			return fmt.Errorf("failed to parse IMG4: %v", err)
		}

		return displayIm4mInfo(img, filePath, jsonOutput, verboseOutput)
	},
}

func displayIm4mInfo(img *img4.Img4, filePath string, jsonOutput, verbose bool) error {
	if jsonOutput {
		data := map[string]interface{}{
			"file":       filepath.Base(filePath),
			"version":    img.Manifest.Version,
			"properties": img.Manifest.Properties,
		}

		if verbose {
			// Add raw manifest data if available
			data["raw_manifest"] = fmt.Sprintf("%x", img.Manifest.ApImg4Ticket.Bytes)
		}

		jsonData, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal IM4M info: %v", err)
		}
		fmt.Println(string(jsonData))
	} else {
		fmt.Printf("%s             %s\n", colorField("File:"), filepath.Base(filePath))
		fmt.Printf("%s %d\n", colorField("Manifest Version:"), img.Manifest.Version)
		
		fmt.Printf("\n%s\n", colorField("Manifest Properties:"))
		for key, value := range img.Manifest.Properties {
			switch v := value.(type) {
			case []byte:
				if verbose {
					fmt.Printf("  %s: %x\n", key, v)
				} else {
					fmt.Printf("  %s: <data:%d bytes>\n", key, len(v))
				}
			default:
				fmt.Printf("  %s: %v\n", key, v)
			}
		}

		if verbose {
			fmt.Printf("\n%s %d bytes\n", colorField("Raw Manifest:"), len(img.Manifest.ApImg4Ticket.Bytes))
		}
	}

	return nil
}

// img4Im4mExtractCmd represents the im4m extract command
var img4Im4mExtractCmd = &cobra.Command{
	Use:           "extract <IMG4|SHSH>",
	Short:         "Extract IM4M manifest from IMG4 or SHSH blob",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		filePath := args[0]
		outputPath := viper.GetString("img4.im4m.extract.output")
		isShsh := viper.GetBool("img4.im4m.extract.shsh")

		if outputPath == "" {
			outputPath = filepath.Clean(filePath) + ".im4m"
		}

		f, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %v", filePath, err)
		}
		defer f.Close()

		var manifestData []byte

		if isShsh {
			// Extract manifest from SHSH blob
			manifestData, err = extractManifestFromShsh(f)
			if err != nil {
				return fmt.Errorf("failed to extract manifest from SHSH blob: %v", err)
			}
		} else {
			// Extract manifest from IMG4
			img, err := img4.Parse(f)
			if err != nil {
				return fmt.Errorf("failed to parse IMG4: %v", err)
			}
			manifestData = img.Manifest.ApImg4Ticket.Bytes
		}

		fmt.Printf("%s             %s\n", colorField("File:"), filepath.Base(filePath))
		fmt.Printf("%s      %s\n", colorField("Output:"), outputPath)
		fmt.Printf("%s        %s\n", colorField("Manifest Size:"), humanize.Bytes(uint64(len(manifestData))))

		return os.WriteFile(outputPath, manifestData, 0644)
	},
}

func extractManifestFromShsh(r io.Reader) ([]byte, error) {
	// For now, this is a placeholder implementation
	// In a full implementation, this would parse SHSH blob format
	// and extract the embedded IM4M manifest
	
	// Read all data to look for IM4M signature
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read SHSH data: %v", err)
	}

	// Look for IM4M signature in the blob
	im4mSig := []byte("IM4M")
	idx := bytes.Index(data, im4mSig)
	if idx == -1 {
		return nil, fmt.Errorf("no IM4M manifest found in SHSH blob")
	}

	// Simple extraction - in reality this would need proper ASN.1 parsing
	// For now, we'll extract from the IM4M signature to a reasonable end point
	manifestStart := idx
	
	// Find the end of the manifest by looking for the next major structure or end of data
	// This is a simplified approach - real implementation would parse ASN.1 structure
	manifestEnd := len(data)
	for i := manifestStart + 4; i < len(data)-3; i++ {
		// Look for potential end markers or next structures
		if bytes.Equal(data[i:i+4], []byte("IM4R")) || 
		   bytes.Equal(data[i:i+4], []byte("IM4P")) {
			manifestEnd = i
			break
		}
	}

	if manifestEnd <= manifestStart+4 {
		return nil, fmt.Errorf("invalid manifest structure in SHSH blob")
	}

	return data[manifestStart:manifestEnd], nil
}