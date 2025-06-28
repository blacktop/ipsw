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
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/commands/extract"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// NOTE:
//   Firmware/isp_bni/adc-aceso-d8x.im4p

func init() {
	FwCmd.AddCommand(camCmd)

	camCmd.Flags().BoolP("info", "i", false, "Print info")
	camCmd.Flags().BoolP("remote", "r", false, "Parse remote IPSW URL")
	camCmd.Flags().StringP("output", "o", "", "Folder to extract files to")
	camCmd.MarkFlagDirname("output")
	viper.BindPFlag("fw.cam.info", camCmd.Flags().Lookup("info"))
	viper.BindPFlag("fw.cam.remote", camCmd.Flags().Lookup("remote"))
	viper.BindPFlag("fw.cam.output", camCmd.Flags().Lookup("output"))
}

// camCmd represents the cam command
var camCmd = &cobra.Command{
	Use:           "cam <IPSW|URL|IM4P>",
	Aliases:       []string{"c"},
	Short:         "Dump MachOs",
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	SilenceUsage:  true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		showInfo := viper.GetBool("fw.cam.info")
		output := viper.GetString("fw.cam.output")
		infile := filepath.Clean(args[0])

		if isZip, err := magic.IsZip(infile); err != nil && !viper.GetBool("fw.cam.remote") {
			return fmt.Errorf("failed to determine if file is a zip: %v", err)
		} else if isZip || viper.GetBool("fw.cam.remote") {
			var out []string
			if viper.GetBool("fw.cam.remote") {
				out, err = extract.Search(&extract.Config{
					URL:     args[0],
					Pattern: "adc.*\\.im4p$",
					Output:  os.TempDir(),
				})
				if err != nil {
					return fmt.Errorf("failed to search for a cam remote IPSW: %v", err)
				}
			} else {
				out, err = extract.Search(&extract.Config{
					IPSW:    infile,
					Pattern: "adc.*\\.im4p$",
					Output:  os.TempDir(),
				})
				if err != nil {
					return fmt.Errorf("failed to search for cam in local IPSW: %v", err)
				}
			}
			for _, f := range out {
				im4p, err := img4.OpenPayload(f)
				if err != nil {
					return fmt.Errorf("failed to open im4p: %v", err)
				}
				if showInfo {
					m, err := macho.NewFile(bytes.NewReader(im4p.Data))
					if err != nil {
						return fmt.Errorf("failed to open macho: %v", err)
					}
					fmt.Println(m.FileTOC.String())
				} else {
					fname := filepath.Join(output, strings.TrimSuffix(infile, filepath.Ext(infile)))
					if err := os.MkdirAll(output, 0o755); err != nil {
						return fmt.Errorf("failed to create output directory: %v", err)
					}
					utils.Indent(log.Info, 2)(fmt.Sprintf("Extracting MachO to file %s", fname))
					if err := os.WriteFile(fname, im4p.Data, 0o644); err != nil {
						return err
					}
				}
				os.Remove(f) // cleanup the extracted im4p file
			}
			return nil
		} else if ok, _ := magic.IsIm4p(args[0]); ok {
			log.Info("Processing IM4P file")
			im4p, err := img4.OpenPayload(infile)
			if err != nil {
				return err
			}
			if showInfo {
				m, err := macho.NewFile(bytes.NewReader(im4p.Data))
				if err != nil {
					return err
				}
				fmt.Println(m.FileTOC.String())
				return nil
			} else {
				fname := strings.TrimSuffix(infile, filepath.Ext(infile))
				if output != "" {
					fname = filepath.Join(output, filepath.Base(fname))
				}
				utils.Indent(log.Info, 2)(fmt.Sprintf("Extracting MachO to file %s", fname))
				return os.WriteFile(fname, im4p.Data, 0o644)
			}
		}

		return fmt.Errorf("unsupported file type")
	},
}
