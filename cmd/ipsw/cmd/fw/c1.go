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
package fw

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/commands/extract"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/ftab"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// NOTE:
//   Firmware/c4000v59/Release/patched/ftab.bin

func init() {
	FwCmd.AddCommand(c1Cmd)

	c1Cmd.Flags().BoolP("info", "i", false, "Print info")
	c1Cmd.Flags().StringP("output", "o", "", "Folder to extract files to")
	c1Cmd.MarkFlagDirname("output")
	viper.BindPFlag("fw.c1.info", c1Cmd.Flags().Lookup("info"))
	viper.BindPFlag("fw.c1.output", c1Cmd.Flags().Lookup("output"))
}

// c1Cmd represents the bb command
var c1Cmd = &cobra.Command{
	Use:     "c1 <IPSW>",
	Aliases: []string{"bb", "baseband"},
	Short:   "🚧 Dump C1 Baseband Firmware",
	Args:    cobra.ExactArgs(1),
	Hidden:  true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		info := viper.GetBool("fw.c1.info")
		output := viper.GetString("fw.c1.output")

		infile := filepath.Clean(args[0])

		if isZip, err := magic.IsZip(infile); err != nil {
			return fmt.Errorf("failed to determine if file is a zip: %v", err)
		} else if isZip {
			out, err := extract.Search(&extract.Config{
				IPSW:    infile,
				Pattern: "c40.*\\/ftab.bin$",
				Output:  output,
			})
			if err != nil {
				return err
			}
			for _, f := range out {
				log.Infof("Parsing %s", f)
				ftab, err := ftab.Open(f)
				if err != nil {
					return err
				}
				defer ftab.Close()
				if info {
					fmt.Println(ftab)
				} else {
					for _, entry := range ftab.Entries {
						fname := filepath.Join(filepath.Dir(f), "extracted", string(entry.Tag[:])+".bin")
						if err := os.MkdirAll(filepath.Dir(fname), 0o755); err != nil {
							return fmt.Errorf("failed to create directory: %v", err)
						}
						if cmp, ok := entry.IsCompressed(); ok {
							log.WithField("entry", fname).Info("Creating (decompressed)")
							data, err := entry.Decompress()
							if err != nil {
								return err
							}
							if len(data) != int(cmp.OriginalSize) {
								utils.Indent(log.Warn, 2)(fmt.Sprintf("decompressed size mismatch: %d != %d", len(data), cmp.OriginalSize))
								log.Warnf("decompressed size mismatch: %d != %d", len(data), cmp.OriginalSize)
							}
							if err := os.WriteFile(fname, data, 0o644); err != nil {
								return err
							}
						} else {
							log.WithField("entry", fname).Info("Creating")
							data, err := io.ReadAll(entry)
							if err != nil {
								return err
							}
							if err := os.WriteFile(fname, data, 0o644); err != nil {
								return err
							}
						}
					}
				}
			}
		} else {
			return fmt.Errorf("unsupported file type: %s", infile)
		}

		return nil
	},
}
