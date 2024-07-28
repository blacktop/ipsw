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
package ota

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/pkg/ota"
	"github.com/blacktop/ipsw/pkg/ota/pbzx"
	"github.com/blacktop/ipsw/pkg/ota/yaa"
	"github.com/dustin/go-humanize"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	otaLsCmd.AddCommand(otaLsPayloadCmd)

	otaLsPayloadCmd.Flags().BoolP("files", "f", false, "Files only")
	otaLsPayloadCmd.Flags().BoolP("dirs", "d", false, "Directories only")

	viper.BindPFlag("ota.ls.payload.files", otaLsPayloadCmd.Flags().Lookup("files"))
	viper.BindPFlag("ota.ls.payload.dirs", otaLsPayloadCmd.Flags().Lookup("dirs"))
}

// otaLsPayloadCmd represents the payload command
var otaLsPayloadCmd = &cobra.Command{
	Use:           "payload <PAYLOAD>|<OTA> <PAYLOAD>",
	Aliases:       []string{"p"},
	Short:         "List contents of a payloadv2 file",
	Args:          cobra.MaximumNArgs(2),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		if viper.GetBool("ota.ls.payload.files") && viper.GetBool("ota.ls.payload.dirs") {
			return fmt.Errorf("cannot use both --files and --dirs flags")
		}

		var aa *yaa.YAA

		if len(args) < 2 {
			isPBZX, err := magic.IsPBZX(filepath.Clean(args[0]))
			if err != nil {
				return fmt.Errorf("failed to check if payload is pbzx: %v", err)
			}
			pf, err := os.Open(filepath.Clean(args[0]))
			if err != nil {
				return fmt.Errorf("failed to open payload: %v", err)
			}
			defer pf.Close()
			if isPBZX {
				var pbuf bytes.Buffer
				if err := pbzx.Extract(context.Background(), pf, &pbuf, runtime.NumCPU()); err != nil {
					return err
				}
				pr := bytes.NewReader(pbuf.Bytes())
				aa, err = yaa.Parse(pr)
				if err != nil {
					return fmt.Errorf("failed to parse payload: %v", err)
				}
			} else {
				aa, err = yaa.Parse(pf)
				if err != nil {
					return fmt.Errorf("failed to parse payload: %v", err)
				}
			}
		} else {
			o, err := ota.Open(filepath.Clean(args[0]))
			if err != nil {
				return fmt.Errorf("failed to open OTA file: %v", err)
			}
			defer o.Close()

			f, err := o.Open(filepath.Clean(args[1]), false)
			if err != nil {
				return fmt.Errorf("failed to open payload: %v", err)
			}

			data, err := io.ReadAll(f)
			if err != nil {
				return fmt.Errorf("failed to read payload: %v", err)
			}

			aa, err = yaa.Parse(bytes.NewReader(data))
			if err != nil {
				return fmt.Errorf("failed to parse payload: %v", err)
			}
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.DiscardEmptyColumns)
		fmt.Fprintf(w, "- [ PAYLOAD ENTRIES ] SIZE: %d BYTES (%s) %s\n\n", aa.FileSize(), humanize.Bytes(uint64(aa.FileSize())), strings.Repeat("-", 50))
		for _, f := range aa.Entries {
			if viper.GetBool("ota.ls.payload.files") && f.Type != yaa.RegularFile {
				continue
			} else if viper.GetBool("ota.ls.payload.dirs") && f.Type != yaa.Directory {
				continue
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", colorMode(f.Mod), colorModTime(f.Mtm.Format(time.RFC3339)), colorSize(humanize.Bytes(uint64(f.Size))), colorName(f.Path))
		}
		w.Flush()

		return nil
	},
}
