//go:build darwin && cgo
// +build darwin,cgo

/*
Copyright © 2021 blacktop

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
package cmd

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/disk/dmg"
	"github.com/blacktop/ipsw/pkg/disk/gpt"
	"github.com/blacktop/ipsw/pkg/disk/mbr"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(dmgCmd)
}

// dmgCmd represents the dmg command
var dmgCmd = &cobra.Command{
	Use:    "dmg",
	Short:  "🚧 Parse DMG file",
	Args:   cobra.MinimumNArgs(1),
	Hidden: true,
	Run: func(cmd *cobra.Command, args []string) {
		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		dmgPath := filepath.Clean(args[0])

		d, err := dmg.Open(dmgPath)
		if err != nil {
			panic(err)
		}
		defer d.Close()

		var g gpt.GUIDPartitionTable

		for _, block := range d.Blocks {
			fmt.Println(block.Name)
			if strings.Contains(block.Name, "MBR") {
				var out bytes.Buffer
				w := bufio.NewWriter(&out)
				if err := block.DecompressChunks(w); err != nil {
					panic(err)
				}
				w.Flush()
				m, err := mbr.NewMasterBootRecord(bytes.NewReader(out.Bytes()))
				if err != nil {
					panic(err)
				}
				fmt.Println("MBR")
				fmt.Println("===")
				fmt.Println("Partitions")
				for _, p := range m.Partitions {
					if p.Type != mbr.Empty {
						fmt.Println(p)
					}
				}
			} else if strings.Contains(block.Name, "GPT Header") {
				var out bytes.Buffer
				w := bufio.NewWriter(&out)
				if err := block.DecompressChunks(w); err != nil {
					panic(err)
				}
				w.Flush()
				if err := binary.Read(bytes.NewReader(out.Bytes()), binary.LittleEndian, &g.Header); err != nil {
					log.Error(err.Error())
				}
			} else if strings.Contains(block.Name, "GPT Table") {
				var out bytes.Buffer
				w := bufio.NewWriter(&out)
				if err := block.DecompressChunks(w); err != nil {
					panic(err)
				}
				w.Flush()
				g.Partitions = make([]gpt.Partition, g.Header.EntriesCount)
				if err := binary.Read(bytes.NewReader(out.Bytes()), binary.LittleEndian, &g.Partitions); err != nil {
					log.Error(err.Error())
				}

				fmt.Println("GPT Header")
				fmt.Println("==========")
				fmt.Println(g.Header)
				fmt.Println("GPT Table")
				fmt.Println("=========")
				fmt.Println("Partitions")
				fmt.Println("----------")
				for _, p := range g.Partitions {
					if !p.IsEmpty() {
						fmt.Println(p)
					}
				}
			}
			if strings.Contains(block.Name, "Apple_APFS") {
				fo, err := os.Create("Apple_APFS.bin")
				if err != nil {
					panic(err)
				}
				defer func() {
					if err := fo.Close(); err != nil {
						panic(err)
					}
				}()
				w := bufio.NewWriter(fo)

				if err := block.DecompressChunks(w); err != nil {
					panic(err)
				}
			}
		}
	},
}
