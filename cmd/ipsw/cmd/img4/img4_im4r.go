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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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
		asJSON := viper.GetBool("img4.im4r.info.json")

		f, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %v", filePath, err)
		}
		defer f.Close()

		data, err := io.ReadAll(f)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %v", filePath, err)
		}

		restoreInfo, err := img4.ParseRestoreInfo(data)
		if err != nil {
			return fmt.Errorf("failed to parse IM4R: %v", err)
		}

		if asJSON {
			jdata, err := json.MarshalIndent(restoreInfo, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal IM4R info: %v", err)
			}
			fmt.Println(string(jdata))
		} else {
			fmt.Println(restoreInfo)
		}

		return nil
	},
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

		im4rData, err := img4.CreateIm4rWithBootNonce(nonce)
		if err != nil {
			return fmt.Errorf("failed to create IM4R: %v", err)
		}

		utils.Indent(log.WithFields(log.Fields{
			"path": outputPath,
			"size": humanize.Bytes(uint64(len(im4rData))),
		}).Info, 2)("Created IM4R")

		return os.WriteFile(outputPath, im4rData, 0644)
	},
}
