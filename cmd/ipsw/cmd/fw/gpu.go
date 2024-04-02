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
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/commands/img4"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	FwCmd.AddCommand(gpuCmd)

	gpuCmd.Flags().StringP("output", "o", "", "Folder to extract files to")
	gpuCmd.MarkFlagDirname("output")
	viper.BindPFlag("fw.gpu.output", gpuCmd.Flags().Lookup("output"))
}

const RTKitMagic = "rkosftab"

type RTKitHeader struct {
	_        [32]byte
	Magic    [8]byte // "rkosftab"
	NumBlobs uint32
	_        uint32
}

type RTKitBlob struct {
	Name   [4]byte
	Offset uint32
	Size   uint32
	_      uint32
}

// gpuCmd represents the gpu command
var gpuCmd = &cobra.Command{
	Use:     "gpu",
	Aliases: []string{"agx"},
	Short:   "Dump MachOs",
	Hidden:  true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		output := viper.GetString("fw.gpu.output")

		dat, err := os.ReadFile(filepath.Clean(args[0]))
		if err != nil {
			return err
		}

		r := bytes.NewReader(dat)

		var hdr RTKitHeader
		if err := binary.Read(r, binary.LittleEndian, &hdr); err != nil {
			return err
		}

		if string(hdr.Magic[:]) != RTKitMagic {
			if !bytes.Contains(dat[:16], []byte("IM4P")) {
				return fmt.Errorf("invalid RTKit header magic: %s; input file might be an im4p (extract via `ipsw img4 extract` first)", string(hdr.Magic[:]))
			}
			tmpDir, err := os.MkdirTemp(os.TempDir(), "gpu")
			if err != nil {
				return err
			}
			defer os.RemoveAll(tmpDir)
			infile := filepath.Join(tmpDir, filepath.Clean(args[0])+".payload")
			log.Warn("IM4P header detected, extracting payload")
			if err := img4.ExtractPayload(filepath.Clean(args[0]), infile, false); err != nil {
				return err
			}
			// reread the extracted file
			dat, err = os.ReadFile(infile)
			if err != nil {
				return err
			}
			r = bytes.NewReader(dat)
			if err := binary.Read(r, binary.LittleEndian, &hdr); err != nil {
				return err
			}
		}

		blobs := make([]RTKitBlob, hdr.NumBlobs)
		if err := binary.Read(r, binary.LittleEndian, &blobs); err != nil {
			return err
		}

		for _, blob := range blobs {
			r.Seek(int64(blob.Offset), 0)
			buf := make([]byte, blob.Size)
			if _, err := r.Read(buf); err != nil {
				return err
			}

			fname := string(blob.Name[:]) + ".bin"
			if len(output) > 0 {
				if err := os.MkdirAll(output, 0o750); err != nil {
					return err
				}
				fname = filepath.Join(output, fname)
			}
			log.WithFields(log.Fields{
				"name":   string(blob.Name[:]),
				"size":   fmt.Sprintf("%#x", blob.Size),
				"offset": fmt.Sprintf("%#x", blob.Offset),
			}).Info("Extracting")
			if err := os.WriteFile(fname, buf, 0o644); err != nil {
				return err
			}
		}

		return nil
	},
}
