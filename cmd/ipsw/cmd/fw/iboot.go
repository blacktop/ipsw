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
package fw

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	// lzfse "github.com/blacktop/go-lzfse"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/lzfse"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	FwCmd.AddCommand(ibootCmd)

	ibootCmd.Flags().StringP("output", "o", "", "Folder to extract files to")
	ibootCmd.MarkFlagDirname("output")
	viper.BindPFlag("fw.iboot.output", ibootCmd.Flags().Lookup("output"))
}

// ibootCmd represents the iboot command
var ibootCmd = &cobra.Command{
	Use:     "iboot <IBOOT_BIN>",
	Aliases: []string{"ib"},
	Short:   "Dump firmwares",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var name string

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		output := viper.GetString("fw.iboot.output")

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
			if len(output) > 0 {
				if err := os.MkdirAll(output, 0o750); err != nil {
					return err
				}
				name = filepath.Join(output, name)
			}
			utils.Indent(log.Info, 2)(fmt.Sprintf("Dumping %s", name))
			if err := os.WriteFile(name, decData, 0o660); err != nil {
				return errors.Wrapf(err, "unabled to write file: %s", name)
			}

			found++
			dat = dat[firstEndMatch+4:]
		}

		return nil
	},
}
