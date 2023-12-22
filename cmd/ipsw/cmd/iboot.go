/*
Copyright © 2018-2024 blacktop

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
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/apex/log"
	// lzfse "github.com/blacktop/go-lzfse"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/lzfse"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(ibootCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// ibootCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// ibootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// ibootCmd represents the iboot command
var ibootCmd = &cobra.Command{
	Use:     "iboot <IBOOT_BIN>",
	Aliases: []string{"ib"},
	Short:   "Dump firmwares",
	Args:    cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var name string

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		f, err := os.Open(args[0])
		if err != nil {
			return errors.Wrapf(err, "unabled to open file: %s", args[0])
		}

		dat, err := io.ReadAll(f)
		if err != nil {
			return errors.Wrapf(err, "unabled to read file: %s", args[0])
		}

		lzfseStart := make([]byte, 4)
		lzfseEnd := make([]byte, 4)
		binary.LittleEndian.PutUint32(lzfseStart, 0x32787662)
		binary.LittleEndian.PutUint32(lzfseEnd, 0x24787662)

		found := 0

		for {
			firstStartMatch := bytes.Index(dat, lzfseStart)
			firstEndMatch := bytes.Index(dat, lzfseEnd)

			if firstStartMatch < 0 || firstEndMatch < 0 {
				break
			}

			decData, err := lzfse.NewDecoder(dat[firstStartMatch : firstEndMatch+4]).DecodeBuffer()
			if err != nil {
				return fmt.Errorf("failed to lzfse decompress embedded firmware: %v", err)
			}

			// decData := lzfse.DecodeBuffer(dat[firstStartMatch : firstEndMatch+4])
			// lr := bytes.NewReader(dat[firstStartMatch : firstEndMatch+4])
			// buf := new(bytes.Buffer)

			// _, err := buf.ReadFrom(lr)
			// if err != nil {
			// 	return errors.Wrap(err, "failed to lzfse decompress embedded firmware")
			// }

			matches := utils.GrepStrings(decData, "AppleSMCFirmware")
			if len(matches) > 0 {
				name = strings.TrimPrefix(matches[0], "@@") + ".bin"
			} else {
				matches = utils.GrepStrings(decData, "AppleStorageProcessorANS2")
				if len(matches) > 0 {
					name = matches[0] + ".bin"
				} else {
					name = fmt.Sprintf("firmware%d.bin", found)
				}
			}

			utils.Indent(log.Info, 2)(fmt.Sprintf("Dumping %s", name))
			os.WriteFile(name, decData, 0660)
			if err != nil {
				return errors.Wrapf(err, "unabled to write file: %s", name)
			}

			// io.Copy(outf, lr)

			found++
			dat = dat[firstEndMatch+4:]
		}

		return nil
	},
}
