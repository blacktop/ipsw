/*
Copyright © 2021 blacktop

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
package cmd

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/apex/log"
	// lzfse "github.com/blacktop/go-lzfse"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/blacktop/ipsw/pkg/lzfse"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	img4Cmd.AddCommand(decImg4Cmd)

	decImg4Cmd.PersistentFlags().StringP("iv-key", "k", "", "AES key")
	decImg4Cmd.PersistentFlags().StringP("output", "o", "", "Output file")
}

// decCmd represents the dec command
var decImg4Cmd = &cobra.Command{
	Use:   "dec <img4>",
	Short: "Decrypt img4 payloads",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		var r io.Reader
		outputFile, _ := cmd.Flags().GetString("output")
		ivkeyStr, _ := cmd.Flags().GetString("iv-key")

		if len(ivkeyStr) == 0 {
			return errors.New("you must supply an ivkey with the flag --iv-key")
		}

		ivkey, _ := hex.DecodeString(ivkeyStr)
		iv := ivkey[:aes.BlockSize]
		key := ivkey[aes.BlockSize:]

		f, err := os.Open(args[0])
		if err != nil {
			return errors.Wrapf(err, "unabled to open file: %s", args[0])
		}

		i, err := img4.ParseIm4p(f)
		if err != nil {
			return errors.Wrap(err, "unabled to parse Im4p")
		}

		block, err := aes.NewCipher(key)
		if err != nil {
			return errors.Wrap(err, "failed to create new AES cipher")
		}

		if len(i.Data) < aes.BlockSize {
			return errors.Errorf("Im4p data too short")
		}

		// CBC mode always works in whole blocks.
		if len(i.Data)%aes.BlockSize != 0 {
			return errors.Errorf("Im4p data is not a multiple of the block size")
		}

		mode := cipher.NewCBCDecrypter(block, iv)

		mode.CryptBlocks(i.Data, i.Data)

		if len(outputFile) == 0 {
			outputFile = args[0] + ".dec"
		}

		of, err := os.Create(outputFile)
		if err != nil {
			return errors.Wrapf(err, "failed to create file: ", outputFile)
		}

		if bytes.Contains(i.Data[:4], []byte("bvx2")) {
			utils.Indent(log.Debug, 2)("Detected LZFSE compression")
			dat, err := lzfse.NewDecoder(i.Data).DecodeBuffer()
			if err != nil {
				return fmt.Errorf("failed to lzfse decompress %s: %v", args[0], err)
			}
			r = bytes.NewReader(dat)
		} else {
			r = bytes.NewReader(i.Data)
		}

		utils.Indent(log.Info, 2)(fmt.Sprintf("Decrypting file to %s", outputFile))
		_, err = io.Copy(of, r)
		if err != nil {
			return errors.Wrapf(err, "failed to decompress to file: ", outputFile)
		}

		return nil
	},
}
