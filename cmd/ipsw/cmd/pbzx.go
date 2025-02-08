/*
Copyright © 2025 blacktop

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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/pkg/ota/pbzx"
	"github.com/dustin/go-humanize"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(pbzxCmd)
}

// pbzxCmd represents the pbzx command
var pbzxCmd = &cobra.Command{
	Use:           "pbzx",
	Short:         "Decompess pbzx files",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	Hidden:        true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		infile := filepath.Clean(args[0])

		if isPBZX, err := magic.IsPBZX(infile); err != nil {
			return err
		} else if !isPBZX {
			return fmt.Errorf("file is not a pbzx file")
		}

		f, err := os.Open(infile)
		if err != nil {
			return err
		}
		defer f.Close()

		finfo, err := f.Stat()
		if err != nil {
			return err
		}

		var pbuf bytes.Buffer
		if err := pbzx.Extract(context.Background(), f, &pbuf, runtime.NumCPU()); err != nil {
			return err
		}

		fname := infile + ".extracted"

		log.WithFields(log.Fields{
			"compressed":   fmt.Sprintf("%d bytes (%s)", finfo.Size(), humanize.IBytes(uint64(finfo.Size()))),
			"decompressed": fmt.Sprintf("%d bytes (%s)", pbuf.Len(), humanize.IBytes(uint64(pbuf.Len()))),
			"output":       fname,
		}).Info("Extracted PBZX file")
		return os.WriteFile(fname, pbuf.Bytes(), 0o644)
	},
}
