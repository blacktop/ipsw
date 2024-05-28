/*
Copyright © 2024 blacktop

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
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/bundle"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// NOTE:
//   Firmware/image4/exclavecore_bundle.t8132.RELEASE.im4p

func init() {
	FwCmd.AddCommand(excCmd)

	excCmd.Flags().BoolP("info", "i", false, "Print info")
	excCmd.Flags().StringP("output", "o", "", "Folder to extract files to")
	excCmd.MarkFlagDirname("output")
	viper.BindPFlag("fw.exclave.info", excCmd.Flags().Lookup("info"))
	viper.BindPFlag("fw.exclave.output", excCmd.Flags().Lookup("output"))
}

// excCmd represents the ane command
var excCmd = &cobra.Command{
	Use:     "exclave",
	Aliases: []string{"exc"},
	Short:   "🚧 Dump MachOs",
	Hidden:  true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		showInfo := viper.GetBool("fw.exclave.info")
		output := viper.GetString("fw.exclave.output")

		bn, err := bundle.Parse(filepath.Clean(args[0]))
		if err != nil {
			return err
		}

		if showInfo {
			fmt.Println(bn)
		} else {
			f, err := os.Open(filepath.Clean(args[0]))
			if err != nil {
				return fmt.Errorf("failed to open file %s: %v", filepath.Clean(args[0]), err)
			}
			defer f.Close()

			for _, bf := range bn.Files {
				fmt.Println(bf)

				fname := filepath.Join(output, bf.Type, bf.Name)
				if err := os.MkdirAll(filepath.Dir(fname), 0o750); err != nil {
					return fmt.Errorf("failed to create directory %s: %v", filepath.Dir(fname), err)
				}

				of, err := os.Create(fname)
				if err != nil {
					return fmt.Errorf("failed to create file %s: %v", fname, err)
				}
				defer of.Close()

				for _, seg := range bf.Segments {
					f.Seek(int64(seg.Offset), io.SeekStart)
					io.CopyN(of, f, int64(seg.Size))
				}
			}
		}

		return nil
	},
}
