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
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/dustin/go-humanize"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	Img4Cmd.AddCommand(img4Im4rCmd)

	// Add subcommands to im4r
	img4Im4rCmd.AddCommand(img4Im4rInfoCmd)
	img4Im4rCmd.AddCommand(img4Im4rCreateCmd)

	// Info command flags
	img4Im4rInfoCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	img4Im4rInfoCmd.MarkZshCompPositionalArgumentFile(1)
	viper.BindPFlag("img4.im4r.info.json", img4Im4rInfoCmd.Flags().Lookup("json"))

	// Create command flags
	img4Im4rCreateCmd.Flags().StringP("boot-nonce", "n", "", "Boot nonce to set (8-byte hex string)")
	img4Im4rCreateCmd.Flags().StringP("output", "o", "", "Output IM4R file path")
	img4Im4rCreateCmd.MarkFlagRequired("boot-nonce")
	img4Im4rCreateCmd.MarkFlagRequired("output")
	img4Im4rCreateCmd.MarkFlagFilename("output")
	viper.BindPFlag("img4.im4r.create.boot-nonce", img4Im4rCreateCmd.Flags().Lookup("boot-nonce"))
	viper.BindPFlag("img4.im4r.create.output", img4Im4rCreateCmd.Flags().Lookup("output"))
}

// img4Im4rCmd represents the im4r command group
var img4Im4rCmd = &cobra.Command{
	Use:   "im4r",
	Short: "IM4R restore info operations",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// img4Im4rInfoCmd represents the im4r info command
var img4Im4rInfoCmd = &cobra.Command{
	Use:           "info <IMG4>",
	Short:         "Display IM4R restore information",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		filePath := args[0]
		jsonOutput := viper.GetBool("img4.im4r.info.json")

		f, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %v", filePath, err)
		}
		defer f.Close()

		restoreInfo, err := img4.ParseIm4r(f)
		if err != nil {
			return fmt.Errorf("failed to parse IM4R: %v", err)
		}

		return displayIm4rInfo(restoreInfo, filePath, jsonOutput, viper.GetBool("verbose"))
	},
}

func displayIm4rInfo(restoreInfo *img4.RestoreInfo, filePath string, jsonOutput, verbose bool) error {
	if jsonOutput {
		data := map[string]any{
			"name":             restoreInfo.Name,
			"boot_nonce":       fmt.Sprintf("%x", restoreInfo.Generator.Data),
			"raw_restore_info": restoreInfo.Generator.Raw,
		}
		jsonData, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal IM4R info: %v", err)
		}
		fmt.Println(string(jsonData))
	} else {

		fmt.Printf("%s       %s\n", colorField("Name:"), restoreInfo.Name)
		fmt.Printf("%s %x\n", colorField("Boot Nonce:"), restoreInfo.Generator.Data)
		if verbose {
			fmt.Printf("%s %d bytes\n", colorField("Generator Data:"), len(restoreInfo.Generator.Data))
			fmt.Printf("%s       %d bytes\n", colorField("Raw Data:"), len(restoreInfo.Generator.Raw))
		}
	}

	return nil
}

// img4Im4rCreateCmd represents the im4r create command
var img4Im4rCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create IM4R restore info with boot nonce",
	Example: heredoc.Doc(`
		# Create IM4R with boot nonce for iOS restore
		❯ ipsw img4 im4r create --boot-nonce 1234567890abcdef --output restore.im4r`),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		bootNonce := viper.GetString("img4.im4r.create.boot-nonce")
		outputPath := viper.GetString("img4.im4r.create.output")

		nonce, err := hex.DecodeString(bootNonce)
		if err != nil {
			return fmt.Errorf("failed to decode boot nonce: %v", err)
		}
		if len(nonce) != 8 {
			return fmt.Errorf("boot nonce must be exactly 8 bytes (16 hex characters), got %d bytes", len(nonce))
		}

		im4rData := createIm4rWithBootNonce(nonce)

		utils.Indent(log.WithFields(log.Fields{
			"path": outputPath,
			"size": humanize.Bytes(uint64(len(im4rData))),
		}).Info, 2)("Created IM4R")

		return os.WriteFile(outputPath, im4rData, 0644)
	},
}

// createIm4rWithBootNonce creates an IM4R structure with a boot nonce
// This creates the same IM4R format as the create command for consistency.
func createIm4rWithBootNonce(nonce []byte) []byte {
	// Use the same implementation as createIm4r in the create command
	return createIm4rData(nonce)
}

// createIm4rData creates IM4R data with the boot nonce - shared implementation
func createIm4rData(nonce []byte) []byte {
	// Create a simplified IM4R structure that contains the boot nonce directly
	// This matches the format expected by both the C and Rust reference implementations

	// Create the generator data containing BNCN + boot nonce
	generatorData := make([]byte, 0, 4+len(nonce))
	generatorData = append(generatorData, []byte("BNCN")...)
	generatorData = append(generatorData, nonce...)

	im4rStruct := struct {
		Name      string `asn1:"ia5"`
		Generator []byte
	}{
		Name:      "IM4R",
		Generator: generatorData,
	}

	im4rData, err := asn1.Marshal(im4rStruct)
	if err != nil {
		// Fallback to simple format if marshaling fails
		return append([]byte("IM4RBNCN"), nonce...)
	}

	return im4rData
}
