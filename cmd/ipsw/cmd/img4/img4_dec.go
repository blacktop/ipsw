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
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"path/filepath"

	"github.com/apex/log"
	icmd "github.com/blacktop/ipsw/internal/commands/img4"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	Img4Cmd.AddCommand(img4DecCmd)

	img4DecCmd.Flags().String("iv-key", "", "AES iv+key")
	img4DecCmd.Flags().StringP("iv", "i", "", "AES iv")
	img4DecCmd.Flags().StringP("key", "k", "", "AES key")
	img4DecCmd.Flags().StringP("output", "o", "", "Output folder")
	img4DecCmd.MarkFlagDirname("output")
	viper.BindPFlag("img4.dec.iv-key", img4DecCmd.Flags().Lookup("iv-key"))
	viper.BindPFlag("img4.dec.iv", img4DecCmd.Flags().Lookup("iv"))
	viper.BindPFlag("img4.dec.key", img4DecCmd.Flags().Lookup("key"))
	viper.BindPFlag("img4.dec.output", img4DecCmd.Flags().Lookup("output"))
}

// decCmd represents the dec command
var img4DecCmd = &cobra.Command{
	Use:     "dec <img4>",
	Aliases: []string{"d"},
	Short:   "Decrypt img4 payloads",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// flags
		ivkeyStr := viper.GetString("img4.dec.iv-key")
		ivStr := viper.GetString("img4.dec.iv")
		keyStr := viper.GetString("img4.dec.key")
		outputDir := viper.GetString("img4.dec.output")
		// validate flags
		if len(ivkeyStr) != 0 && (len(ivStr) != 0 || len(keyStr) != 0) {
			return fmt.Errorf("cannot specify both --iv-key AND --iv/--key")
		} else if len(ivkeyStr) == 0 && (len(ivStr) == 0 || len(keyStr) == 0) {
			return fmt.Errorf("must specify either --iv-key OR --iv/--key")
		}

		infile := filepath.Clean(args[0])
		outfile := infile + ".dec"

		if outputDir != "" {
			outfile = filepath.Join(outputDir, filepath.Base(outfile))
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
				return fmt.Errorf("failed to decode --iv-key: %v", err)
			}
			key, err = hex.DecodeString(keyStr)
			if err != nil {
				return fmt.Errorf("failed to decode --iv-key: %v", err)
			}
		}
		utils.Indent(log.Info, 2)(fmt.Sprintf("Decrypting file to %s", outfile))
		return icmd.DecryptPayload(infile, outfile, iv, key)
	},
}
