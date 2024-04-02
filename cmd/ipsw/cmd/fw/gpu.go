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
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	FwCmd.AddCommand(gpuCmd)
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
			return fmt.Errorf("invalid RTKit header magic: %s; input file might be an im4p (extract via `ipsw img4 extract` first)", string(hdr.Magic[:]))
		}

		blobs := make([]RTKitBlob, hdr.NumBlobs)
		if err := binary.Read(r, binary.LittleEndian, &blobs); err != nil {
			return err
		}

		for _, blob := range blobs {
			log.Infof("Name: %s Offset: 0x%x Size: 0x%x", string(blob.Name[:]), blob.Offset, blob.Size)
			r.Seek(int64(blob.Offset), 0)
			buf := make([]byte, blob.Size)
			if _, err := r.Read(buf); err != nil {
				return err
			}
			log.Infof("Writing %s.bin", string(blob.Name[:]))
			if err := os.WriteFile(string(blob.Name[:])+".bin", buf, 0644); err != nil {
				return err
			}
		}

		return nil
	},
}
