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
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// NOTE:
//   Firmware/ave/AppleAVE2FW.im4p          (older devices, e.g. iPhone11/12-era)
//   Firmware/ave/AppleAVE2FW_H17D.im4p     (newer devices, board-suffixed)
//   both are a plain arm64e MH_PRELOAD MachO

// aveFwPattern matches the AVE firmware IM4P payloads shipped in an IPSW. The
// board suffix is optional (AppleAVE2FW.im4p vs AppleAVE2FW_<board>.im4p).
const aveFwPattern = `Firmware/ave/AppleAVE2FW.*\.im4p$`

func init() {
	FwCmd.AddCommand(aveCmd)

	aveCmd.Flags().BoolP("info", "i", false, "Print info")
	aveCmd.Flags().BoolP("remote", "r", false, "Parse remote IPSW URL")
	aveCmd.Flags().StringP("output", "o", "", "Folder to extract files to")
	aveCmd.MarkFlagDirname("output")
	viper.BindPFlag("fw.ave.info", aveCmd.Flags().Lookup("info"))
	viper.BindPFlag("fw.ave.remote", aveCmd.Flags().Lookup("remote"))
	viper.BindPFlag("fw.ave.output", aveCmd.Flags().Lookup("output"))
}

// aveCmd represents the ave command
var aveCmd = &cobra.Command{
	Use:           "ave <IPSW|URL|IM4P>",
	Short:         "Dump AVE (Apple Video Encoder) MachOs",
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		// flags
		showInfo := viper.GetBool("fw.ave.info")
		output := viper.GetString("fw.ave.output")
		infile := filepath.Clean(args[0])

		dowork := func(input, outDir string) error {
			im4p, err := img4.OpenPayload(input)
			if err != nil {
				return fmt.Errorf("failed to open im4p: %v", err)
			}
			if im4p.Encrypted {
				return fmt.Errorf("AVE payload %s is encrypted (decryption not supported)", filepath.Base(input))
			}
			data, err := im4p.GetData()
			if err != nil {
				return fmt.Errorf("failed to get im4p payload data: %v", err)
			}
			if ok, err := magic.IsMachOData(data); err != nil {
				return err
			} else if !ok {
				return fmt.Errorf("AVE payload %s is not a MachO", filepath.Base(input))
			}
			if showInfo {
				m, err := macho.NewFile(bytes.NewReader(data))
				if err != nil {
					return fmt.Errorf("failed to parse AVE MachO: %v", err)
				}
				if v := rtkitVersion(data); v != "" {
					utils.Indent(log.WithField("version", v).Info, 2)(filepath.Base(input))
				}
				fmt.Println(m.FileTOC.String())
				return nil
			}
			fname := strings.TrimSuffix(filepath.Base(input), filepath.Ext(input)) + ".macho"
			if outDir != "" {
				if err := os.MkdirAll(outDir, 0o755); err != nil {
					return fmt.Errorf("failed to create output directory: %v", err)
				}
				fname = filepath.Join(outDir, fname)
			}
			utils.Indent(log.Info, 2)(fmt.Sprintf("Extracting MachO to file %s", fname))
			return os.WriteFile(fname, data, 0o644)
		}

		if isZip, err := magic.IsZip(infile); err != nil && !viper.GetBool("fw.ave.remote") {
			return fmt.Errorf("failed to determine if file is a zip: %v", err)
		} else if isZip || viper.GetBool("fw.ave.remote") {
			var out []string
			if viper.GetBool("fw.ave.remote") {
				out, err = extract.Search(&extract.Config{
					URL:     args[0],
					Pattern: aveFwPattern,
					Output:  os.TempDir(),
				})
				if err != nil {
					return fmt.Errorf("failed to search for ave in remote IPSW: %v", err)
				}
			} else {
				out, err = extract.Search(&extract.Config{
					IPSW:    infile,
					Pattern: aveFwPattern,
					Output:  os.TempDir(),
				})
				if err != nil {
					return fmt.Errorf("failed to search for ave in local IPSW: %v", err)
				}
			}
			if len(out) == 0 {
				return fmt.Errorf("no AVE firmware (%s) found", aveFwPattern)
			}
			for _, f := range out {
				if err := dowork(f, output); err != nil {
					return err
				}
				if err := os.Remove(f); err != nil {
					log.Debugf("failed to remove temp im4p %s: %v", f, err)
				}
			}
			return nil
		} else if ok, _ := magic.IsIm4p(infile); ok {
			outDir := output
			if outDir == "" {
				outDir = filepath.Dir(infile) // default: extract next to the input im4p
			}
			return dowork(infile, outDir)
		}

		return fmt.Errorf("unsupported file type (expected IPSW, URL, or AVE .im4p)")
	},
}
