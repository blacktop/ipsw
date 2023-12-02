/*
Copyright © 2018-2023 blacktop

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

	"github.com/apex/log"
	icmd "github.com/blacktop/ipsw/internal/commands/img4"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	Img4Cmd.AddCommand(decImg4Cmd)

	decImg4Cmd.PersistentFlags().String("iv-key", "", "AES iv+key")
	decImg4Cmd.PersistentFlags().StringP("iv", "i", "", "AES iv")
	decImg4Cmd.PersistentFlags().StringP("key", "k", "", "AES key")
	decImg4Cmd.PersistentFlags().StringP("output", "o", "", "Output file")
}

// decCmd represents the dec command
var decImg4Cmd = &cobra.Command{
	Use:     "dec <img4>",
	Aliases: []string{"d"},
	Short:   "Decrypt img4 payloads",
	Args:    cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// flags
		outputFile, _ := cmd.Flags().GetString("output")
		ivkeyStr, _ := cmd.Flags().GetString("iv-key")
		ivStr, _ := cmd.Flags().GetString("iv")
		keyStr, _ := cmd.Flags().GetString("key")
		// validate flags
		if len(ivkeyStr) != 0 && (len(ivStr) != 0 || len(keyStr) != 0) {
			return fmt.Errorf("cannot specify both --iv-key AND --iv/--key")
		} else if len(ivkeyStr) == 0 && (len(ivStr) == 0 || len(keyStr) == 0) {
			return fmt.Errorf("must specify either --iv-key OR --iv/--key")
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

		return icmd.DecryptPayload(args[0], outputFile, iv, key)
	},
}
