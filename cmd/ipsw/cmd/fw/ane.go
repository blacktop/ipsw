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
	"regexp"
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
//   Firmware/ane/h17_ane0_fw_hyperion_j71y.im4p (IM4P type 'anef', uncompressed MH_PRELOAD MachO)

// aneFwPattern matches the ANE firmware IM4P payloads shipped in an IPSW.
const aneFwPattern = `Firmware/ane/.*\.im4p$`

// rtkitVersionRe extracts the RTKit version string (e.g. "RTKit-3255.120.11.release").
var rtkitVersionRe = regexp.MustCompile(`RTKit-[0-9][0-9A-Za-z.]+`)

func init() {
	FwCmd.AddCommand(aneCmd)

	aneCmd.Flags().BoolP("info", "i", false, "Print info")
	aneCmd.Flags().BoolP("remote", "r", false, "Parse remote IPSW URL")
	aneCmd.Flags().StringP("output", "o", "", "Folder to extract files to")
	aneCmd.MarkFlagDirname("output")
	viper.BindPFlag("fw.ane.info", aneCmd.Flags().Lookup("info"))
	viper.BindPFlag("fw.ane.remote", aneCmd.Flags().Lookup("remote"))
	viper.BindPFlag("fw.ane.output", aneCmd.Flags().Lookup("output"))
}

// aneCmd represents the ane command
var aneCmd = &cobra.Command{
	Use:           "ane <IPSW|URL|IM4P>",
	Short:         "Dump ANE (Apple Neural Engine) MachOs",
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		// flags
		showInfo := viper.GetBool("fw.ane.info")
		output := viper.GetString("fw.ane.output")
		infile := filepath.Clean(args[0])

		dowork := func(input, outDir string) error {
			im4p, err := img4.OpenPayload(input)
			if err != nil {
				return fmt.Errorf("failed to open im4p: %v", err)
			}
			if im4p.Encrypted {
				return fmt.Errorf("ANE payload %s is encrypted (decryption not supported)", filepath.Base(input))
			}
			data, err := im4p.GetData()
			if err != nil {
				return fmt.Errorf("failed to get im4p payload data: %v", err)
			}
			if ok, err := magic.IsMachOData(data); err != nil {
				return err
			} else if !ok {
				return fmt.Errorf("ANE payload %s is not a MachO", filepath.Base(input))
			}
			if showInfo {
				m, err := macho.NewFile(bytes.NewReader(data))
				if err != nil {
					return fmt.Errorf("failed to parse ANE MachO: %v", err)
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

		if isZip, err := magic.IsZip(infile); err != nil && !viper.GetBool("fw.ane.remote") {
			return fmt.Errorf("failed to determine if file is a zip: %v", err)
		} else if isZip || viper.GetBool("fw.ane.remote") {
			var out []string
			if viper.GetBool("fw.ane.remote") {
				out, err = extract.Search(&extract.Config{
					URL:     args[0],
					Pattern: aneFwPattern,
					Output:  os.TempDir(),
				})
				if err != nil {
					return fmt.Errorf("failed to search for ane in remote IPSW: %v", err)
				}
			} else {
				out, err = extract.Search(&extract.Config{
					IPSW:    infile,
					Pattern: aneFwPattern,
					Output:  os.TempDir(),
				})
				if err != nil {
					return fmt.Errorf("failed to search for ane in local IPSW: %v", err)
				}
			}
			if len(out) == 0 {
				return fmt.Errorf("no ANE firmware (%s) found", aneFwPattern)
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

		return fmt.Errorf("unsupported file type (expected IPSW, URL, or ANE .im4p)")
	},
}

// rtkitVersion returns the RTKit version string embedded in the ANE firmware
// MachO (e.g. "RTKit-3255.120.11.release"), or "" if it cannot be found. The
// string lives in __TEXT.__const on current builds, so the whole payload is
// scanned rather than a single section.
func rtkitVersion(data []byte) string {
	return string(rtkitVersionRe.Find(data))
}
