/*
Copyright © 2018-2022 blacktop

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
	"fmt"
	"io/ioutil"
	"os"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/blacktop/ipsw/pkg/lzfse"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	Img4Cmd.AddCommand(img4ExtractCmd)

	img4ExtractCmd.MarkZshCompPositionalArgumentFile(1)
}

// img4ExtractCmd represents the extract command
var img4ExtractCmd = &cobra.Command{
	Use:   "extract <img4>",
	Short: "Extract img4 payloads",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		f, err := os.Open(args[0])
		if err != nil {
			return errors.Wrapf(err, "unabled to open file: %s", args[0])
		}
		defer f.Close()

		i, err := img4.ParseIm4p(f)
		if err != nil {
			return errors.Wrap(err, "unabled to parse Im4p")
		}

		outFile := args[0] + ".payload"
		utils.Indent(log.Info, 2)(fmt.Sprintf("Exracting payload to file %s", outFile))

		if bytes.Contains(i.Data[:4], []byte("bvx2")) {
			utils.Indent(log.Debug, 2)("Detected LZFSE compression")
			dat, err := lzfse.NewDecoder(i.Data).DecodeBuffer()
			if err != nil {
				return fmt.Errorf("failed to lzfse decompress %s: %v", args[0], err)
			}

			err = ioutil.WriteFile(outFile, dat, 0660)
			if err != nil {
				return errors.Wrapf(err, "failed to write file: ", outFile)
			}
		} else {
			err = ioutil.WriteFile(outFile, i.Data, 0660)
			if err != nil {
				return errors.Wrapf(err, "failed to write file: ", outFile)
			}
		}

		return nil
	},
}
