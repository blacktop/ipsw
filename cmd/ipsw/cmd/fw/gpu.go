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
	"io"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/commands/extract"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/pkg/ftab"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	FwCmd.AddCommand(gpuCmd)

	gpuCmd.Flags().BoolP("remote", "r", false, "Parse remote IPSW URL")
	gpuCmd.Flags().StringP("output", "o", "", "Folder to extract files to")
	gpuCmd.MarkFlagDirname("output")
	viper.BindPFlag("fw.gpu.remote", gpuCmd.Flags().Lookup("remote"))
	viper.BindPFlag("fw.gpu.output", gpuCmd.Flags().Lookup("output"))
}

// gpuCmd represents the gpu command
var gpuCmd = &cobra.Command{
	Use:           "gpu <IPSW|URL|IM4P|FTAB>",
	Aliases:       []string{"agx"},
	Short:         "Dump MachOs",
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	SilenceUsage:  true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		infile := filepath.Clean(args[0])

		dowork := func(ftab *ftab.Ftab, output string) error {
			for _, entry := range ftab.Entries {
				fname := filepath.Join(output, "extracted", string(entry.Tag[:])+".bin")
				if err := os.MkdirAll(filepath.Dir(fname), 0o755); err != nil {
					return fmt.Errorf("failed to create directory: %v", err)
				}
				data, err := io.ReadAll(entry)
				if err != nil {
					return fmt.Errorf("failed to read ftab entry: %v", err)
				}
				log.WithFields(log.Fields{
					"name":   string(entry.Tag[:]),
					"size":   fmt.Sprintf("%#x", entry.Size),
					"offset": fmt.Sprintf("%#x", entry.Offset),
				}).Info("Extracting")
				if err := os.WriteFile(fname, data, 0o644); err != nil {
					return fmt.Errorf("failed to write data to file: %v", err)
				}
			}
			return nil
		}

		if isZip, err := magic.IsZip(infile); err != nil && !viper.GetBool("fw.gpu.remote") {
			return fmt.Errorf("failed to determine if file is a zip: %v", err)
		} else if isZip || viper.GetBool("fw.gpu.remote") {
			var out []string
			if viper.GetBool("fw.gpu.remote") {
				out, err = extract.Search(&extract.Config{
					URL:     args[0],
					Pattern: "armfw_.*.im4p$",
					Output:  viper.GetString("fw.gpu.output"),
				})
				if err != nil {
					return fmt.Errorf("failed to search for gpu in remote IPSW: %v", err)
				}
			} else {
				out, err = extract.Search(&extract.Config{
					IPSW:    infile,
					Pattern: "armfw_.*.im4p$",
					Output:  viper.GetString("fw.gpu.output"),
				})
				if err != nil {
					return fmt.Errorf("failed to search for gpu in local IPSW: %v", err)
				}
			}
			for _, f := range out {
				log.Infof("Parsing %s", f)
				im4p, err := img4.OpenPayload(f)
				if err != nil {
					return err
				}
				ftab, err := ftab.Parse(bytes.NewReader(im4p.Data))
				if err != nil {
					return fmt.Errorf("failed to parse ftab: %v", err)
				}
				if err := dowork(ftab, filepath.Dir(f)); err != nil {
					return err
				}
			}
		} else if isIm4p, _ := magic.IsIm4p(infile); isIm4p {
			log.Info("Processing IM4P file")
			im4p, err := img4.OpenPayload(infile)
			if err != nil {
				return err
			}
			ftab, err := ftab.Parse(bytes.NewReader(im4p.Data))
			if err != nil {
				return fmt.Errorf("failed to parse ftab: %v", err)
			}
			if err := dowork(ftab, viper.GetString("fw.gpu.output")); err != nil {
				return err
			}
		} else {
			ftab, err := ftab.Open(infile)
			if err != nil {
				return fmt.Errorf("failed to parse ftab: %v", err)
			}
			defer ftab.Close()
			if err := dowork(ftab, viper.GetString("fw.gpu.output")); err != nil {
				return err
			}
		}

		return nil
	},
}
