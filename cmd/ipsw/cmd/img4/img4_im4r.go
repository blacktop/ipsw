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
	"os"
	"path/filepath"
	"regexp"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/dustin/go-humanize"
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
	img4Im4rCreateCmd.MarkFlagRequired("boot-nonce")
	img4Im4rCreateCmd.Flags().StringP("output", "o", "", "Output IM4R file path")
	img4Im4rCreateCmd.MarkFlagRequired("output")
	img4Im4rCreateCmd.MarkFlagFilename("output")
	viper.BindPFlag("img4.im4r.create.boot-nonce", img4Im4rCreateCmd.Flags().Lookup("boot-nonce"))
	viper.BindPFlag("img4.im4r.create.output", img4Im4rCreateCmd.Flags().Lookup("output"))
}

// img4Im4rCmd represents the im4r command group
var img4Im4rCmd = &cobra.Command{
	Use:     "im4r",
	Aliases: []string{"r"},
	Short:   "IM4R restore info operations",
	Args:    cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// img4Im4rInfoCmd represents the im4r info command
var img4Im4rInfoCmd = &cobra.Command{
	Use:     "info <IMG4>",
	Aliases: []string{"i"},
	Short:   "Display IM4R restore information",
	Example: heredoc.Doc(`
		# Display IM4R restore info from IMG4 file
		❯ ipsw img4 im4r info kernel.img4

		# Output as JSON
		❯ ipsw img4 im4r info --json kernel.img4`),
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		im4r, err := img4.OpenRestoreInfo(filepath.Clean(args[0]))
		if err != nil {
			return fmt.Errorf("failed to parse IM4R: %v", err)
		}

		if viper.GetBool("img4.im4r.info.json") {
			jdata, err := json.Marshal(im4r)
			if err != nil {
				return fmt.Errorf("failed to marshal IM4R info: %v", err)
			}
			fmt.Println(string(jdata))
		} else {
			fmt.Println(im4r)
		}

		return nil
	},
}

// img4Im4rCreateCmd represents the im4r create command
var img4Im4rCreateCmd = &cobra.Command{
	Use:     "create",
	Aliases: []string{"c"},
	Short:   "Create IM4R restore info with boot nonce",
	Example: heredoc.Doc(`
		# Create IM4R with boot nonce for iOS restore
		❯ ipsw img4 im4r create --boot-nonce 1234567890abcdef --output restore.im4r`),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// flags
		bootNonce := viper.GetString("img4.im4r.create.boot-nonce")
		outputPath := viper.GetString("img4.im4r.create.output")
		// validate flags
		if bootNonce != "" {
			if !regexp.MustCompile("^[0-9a-fA-F]{16}$").MatchString(bootNonce) {
				return fmt.Errorf("--boot-nonce must be exactly 16 hex characters")
			}
		}

		nonce, err := hex.DecodeString(bootNonce)
		if err != nil {
			return fmt.Errorf("failed to decode boot nonce: %v", err)
		}
		if len(nonce) != 8 {
			return fmt.Errorf("boot nonce must be exactly 8 bytes (16 hex characters), got %d bytes", len(nonce))
		}

		im4r, err := img4.CreateRestoreInfo(nonce)
		if err != nil {
			return fmt.Errorf("failed to create IM4R: %v", err)
		}

		im4rData, err := im4r.Marshal()
		if err != nil {
			return fmt.Errorf("failed to marshal IM4R: %v", err)
		}

		log.WithFields(log.Fields{
			"path": outputPath,
			"size": humanize.Bytes(uint64(len(im4rData))),
		}).Info("Created IM4R")

		return os.WriteFile(filepath.Clean(outputPath), im4rData, 0644)
	},
}
