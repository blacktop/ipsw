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
	"github.com/blacktop/ipsw/pkg/bundle"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// NOTE:
//   Firmware/AOP/aopfw-iphone16aop.RELEASE.im4p
//   Firmware/AOP2/aop2fw-iphone17aop2.RELEASE.im4p

func init() {
	FwCmd.AddCommand(aopCmd)

	aopCmd.Flags().BoolP("info", "i", false, "Print info")
	aopCmd.Flags().BoolP("remote", "r", false, "Parse remote IPSW URL")
	aopCmd.Flags().StringP("output", "o", "", "Folder to extract files to")
	aopCmd.MarkFlagDirname("output")
	viper.BindPFlag("fw.aop.info", aopCmd.Flags().Lookup("info"))
	viper.BindPFlag("fw.aop.remote", aopCmd.Flags().Lookup("remote"))
	viper.BindPFlag("fw.aop.output", aopCmd.Flags().Lookup("output"))
}

// aopCmd represents the aop command
var aopCmd = &cobra.Command{
	Use:           "aop <IPSW|IM4P|BUNDLE>",
	Short:         "Dump MachOs",
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	SilenceUsage:  true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		showInfo := viper.GetBool("fw.aop.info")
		output := viper.GetString("fw.aop.output")
		infile := filepath.Clean(args[0])

		if isZip, err := magic.IsZip(infile); err != nil && !viper.GetBool("fw.aop.remote") {
			return fmt.Errorf("failed to determine if file is a zip: %v", err)
		} else if isZip || viper.GetBool("fw.aop.remote") {
			var out []string
			if viper.GetBool("fw.aop.remote") {
				out, err = extract.Search(&extract.Config{
					URL:     args[0],
					Pattern: "aop.*fw.*\\.im4p$",
					Output:  os.TempDir(),
				})
				if err != nil {
					return fmt.Errorf("failed to search for aop in remote IPSW: %v", err)
				}
			} else {
				out, err = extract.Search(&extract.Config{
					IPSW:    infile,
					Pattern: "aop.*fw.*\\.im4p$",
					Output:  os.TempDir(),
				})
				if err != nil {
					return fmt.Errorf("failed to search for aop in local IPSW: %v", err)
				}
			}
			for _, f := range out {
				if ok, _ := magic.IsIm4p(f); ok {
					im4p, err := img4.OpenPayload(f)
					if err != nil {
						return err
					}
					if showInfo {
						if isMacho, err := magic.IsMachOData(im4p.Data); err != nil {
							return err
						} else if isMacho {
							m, err := macho.NewFile(bytes.NewReader(im4p.Data))
							if err != nil {
								return err
							}
							fmt.Println(m.FileTOC.String())
						} else {
							bund, err := bundle.Parse(bytes.NewReader(im4p.Data))
							if err != nil {
								return err
							}
							fmt.Println(bund)
						}
					} else {
						if isMacho, err := magic.IsMachOData(im4p.Data); err != nil {
							return err
						} else if isMacho {
							fname := strings.TrimSuffix(f, filepath.Ext(f))
							if output != "" {
								fname = filepath.Join(output, filepath.Base(fname))
							}
							utils.Indent(log.Info, 2)(fmt.Sprintf("Extracting MachO to file %s", fname))
							if err := os.WriteFile(fname, im4p.Data, 0o644); err != nil {
								return fmt.Errorf("failed to write file %s: %v", fname, err)
							}
						} else {
							// FIXME: extract files
							// return fmt.Errorf("extraction not yet supported for this file type")
							bn, err := bundle.Parse(bytes.NewReader(im4p.Data))
							if err != nil {
								return err
							}
							if bn.Type == 4 {
								return bn.DumpFiles(output)
							}
							return fmt.Errorf("extraction not yet supported for this bundle type: %v", bn.Type)
						}
					}
				}
			}
			return nil
		} else if ok, _ := magic.IsIm4p(infile); ok {
			im4p, err := img4.OpenPayload(infile)
			if err != nil {
				return err
			}
			if showInfo {
				if isMacho, err := magic.IsMachOData(im4p.Data); err != nil {
					return err
				} else if isMacho {
					m, err := macho.NewFile(bytes.NewReader(im4p.Data))
					if err != nil {
						return err
					}
					fmt.Println(m.FileTOC.String())
				} else {
					bund, err := bundle.Parse(bytes.NewReader(im4p.Data))
					if err != nil {
						return err
					}
					fmt.Println(bund)
				}
				return nil
			} else {
				if isMacho, err := magic.IsMachOData(im4p.Data); err != nil {
					return err
				} else if isMacho {
					fname := strings.TrimSuffix(infile, filepath.Ext(infile))
					if output != "" {
						fname = filepath.Join(output, filepath.Base(fname))
					}
					utils.Indent(log.Info, 2)(fmt.Sprintf("Extracting MachO to file %s", fname))
					if err := os.WriteFile(fname, im4p.Data, 0o644); err != nil {
						return fmt.Errorf("failed to write file %s: %v", fname, err)
					}
				} else {
					bn, err := bundle.Parse(bytes.NewReader(im4p.Data))
					if err != nil {
						return err
					}
					if bn.Type == 4 {
						return bn.DumpFiles(output)
					}
					return fmt.Errorf("extraction not yet supported for this bundle type: %v", bn.Type)
				}
			}
		} else {
			bn, err := bundle.Open(infile)
			if err != nil {
				return fmt.Errorf("failed to open bundle: %v", err)
			}
			defer bn.Close()
			if showInfo {
				fmt.Println(bn)
			} else {
				if bn.Type == 4 {
					return bn.DumpFiles(output)
				}
				return fmt.Errorf("extraction not yet supported for this bundle type: %v", bn.Type)
			}
		}

		return fmt.Errorf("unsupported file type")
	},
}
