/*
Copyright © 2026 blacktop

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
	"github.com/blacktop/ipsw/pkg/bundle"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// NOTE:
//   Firmware/dcp/t8130dcp.im4p
//   Firmware/dcp/t8130dcp_restore.im4p

// dcpFwPattern matches the DCP firmware IM4P payloads shipped in an IPSW.
const dcpFwPattern = `Firmware/dcp/.*\.im4p$`

// writeMachO writes a Mach-O blob next to (or under output) the input file,
// trimming the input extension and appending ".macho".
func writeMachO(input, output string, data []byte) error {
	if output == "" {
		output = filepath.Dir(input) // default: write next to the input file
	}
	if err := os.MkdirAll(output, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}
	base := strings.TrimSuffix(filepath.Base(input), filepath.Ext(input))
	fname := filepath.Join(output, base+".macho")
	utils.Indent(log.Info, 2)(fmt.Sprintf("Extracting MachO to file %s", fname))
	return os.WriteFile(fname, data, 0o644)
}

func init() {
	FwCmd.AddCommand(dcpCmd)

	dcpCmd.Flags().BoolP("info", "i", false, "Print info")
	dcpCmd.Flags().BoolP("remote", "r", false, "Parse remote IPSW URL")
	dcpCmd.Flags().StringP("output", "o", "", "Folder to extract files to")
	dcpCmd.MarkFlagDirname("output")
	viper.BindPFlag("fw.dcp.info", dcpCmd.Flags().Lookup("info"))
	viper.BindPFlag("fw.dcp.remote", dcpCmd.Flags().Lookup("remote"))
	viper.BindPFlag("fw.dcp.output", dcpCmd.Flags().Lookup("output"))
}

// dcpCmd represents the dcp command
var dcpCmd = &cobra.Command{
	Use:           "dcp <IPSW|URL|IM4P|BUNDLE>",
	Aliases:       []string{"d"},
	Short:         "Dump MachOs",
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		// flags
		showInfo := viper.GetBool("fw.dcp.info")
		output := viper.GetString("fw.dcp.output")
		infile := filepath.Clean(args[0])

		dowork := func(input, output string) error {
			im4p, err := img4.OpenPayload(input)
			if err != nil {
				return fmt.Errorf("failed to open im4p: %v", err)
			}
			data, err := im4p.GetData()
			if err != nil {
				return fmt.Errorf("failed to get im4p payload data: %v", err)
			}

			if ok, err := magic.IsMachOData(data); err != nil {
				return err
			} else if ok {
				if showInfo {
					m, err := macho.NewFile(bytes.NewReader(data))
					if err != nil {
						return fmt.Errorf("failed to open macho: %v", err)
					}
					fmt.Println(m.FileTOC.String())
					return nil
				}
				return writeMachO(input, output, data)
			}

			bn, err := bundle.Parse(bytes.NewReader(data))
			if err != nil {
				return fmt.Errorf("failed to parse dcp payload as bundle: %v", err)
			}
			if showInfo {
				fmt.Println(bn)
				return nil
			}
			runtime, err := bn.ExtractRuntimeMachO()
			if err != nil {
				return fmt.Errorf("failed to extract runtime MachO from bundle: %v", err)
			}
			return writeMachO(input, output, runtime)
		}

		if isZip, err := magic.IsZip(infile); err != nil && !viper.GetBool("fw.dcp.remote") {
			return fmt.Errorf("failed to determine if file is a zip: %v", err)
		} else if isZip || viper.GetBool("fw.dcp.remote") {
			var out []string
			if viper.GetBool("fw.dcp.remote") {
				out, err = extract.Search(&extract.Config{
					URL:     args[0],
					Pattern: dcpFwPattern,
					Output:  output,
				})
				if err != nil {
					return fmt.Errorf("failed to extract dcp from remote IPSW: %v", err)
				}
			} else {
				out, err = extract.Search(&extract.Config{
					IPSW:    infile,
					Pattern: dcpFwPattern,
					Output:  output,
				})
				if err != nil {
					return fmt.Errorf("failed to extract dcp from IPSW: %v", err)
				}
			}
			for _, f := range out {
				log.Infof("Parsing %s", f)
				if err := dowork(f, filepath.Dir(f)); err != nil {
					return err
				}
			}
			return nil
		} else if ok, _ := magic.IsIm4p(infile); ok {
			return dowork(infile, output)
		}

		// direct DNUB/BUND bundle input
		bn, err := bundle.Open(infile)
		if err != nil {
			return fmt.Errorf("failed to open bundle: %v", err)
		}
		defer bn.Close()
		if showInfo {
			fmt.Println(bn)
			return nil
		}
		runtime, err := bn.ExtractRuntimeMachO()
		if err != nil {
			return fmt.Errorf("failed to extract runtime MachO from bundle: %v", err)
		}
		return writeMachO(infile, output, runtime)
	},
}
