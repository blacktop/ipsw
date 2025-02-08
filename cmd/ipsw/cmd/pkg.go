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
package cmd

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/apex/log"
	"github.com/spf13/cobra"

	"github.com/blacktop/go-macho/pkg/cpio"
	"github.com/blacktop/go-macho/pkg/xar"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/pkg/ota/pbzx"
)

func init() {
	rootCmd.AddCommand(pkgCmd)
}

// pkgCmd represents the pkg command
var pkgCmd = &cobra.Command{
	Use:           "pkg",
	Short:         "List contents of a DMG/PKG file",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		infile := filepath.Clean(args[0])

		isDMG, err := magic.IsDMG(infile)
		if err != nil {
			return err
		}
		if !isDMG {
			if isXar, err := magic.IsXar(infile); err != nil {
				return err
			} else if !isXar {
				return fmt.Errorf("file is not a dmg OR pkg file")
			}
		}

		if isDMG {
			log.Fatal("DMG files are not supported yet")
			// d, err := dmg.Open(infile, nil)
			// if err != nil {
			// 	return err
			// }
			// defer d.Close()
			// if err := d.Load(); err != nil {
			// 	return err
			// }
		} else { // PKG/XAR
			pkg, err := xar.Open(infile)
			if err != nil {
				return err
			}
			defer pkg.Close()
			if !pkg.ValidSignature() {
				log.Warn("PKG/XAR file signature is invalid, this may be a corrupted file")
			}
			var names []string
			var payload *xar.File
			for _, file := range pkg.Files {
				names = append(names, file.Name)
				if strings.Contains(file.Name, "Payload") {
					payload = file
				}
			}
			sort.StringSlice(names).Sort()
			for _, name := range names {
				fmt.Println(name)
			}
			if payload != nil {
				f, err := payload.Open()
				if err != nil {
					return err
				}
				defer f.Close()
				log.Infof("Parsing %s...", payload.Name)
				var pbuf bytes.Buffer
				if err := pbzx.Extract(context.Background(), f, &pbuf, runtime.NumCPU()); err != nil {
					return err
				}
				cr, err := cpio.NewReader(bytes.NewReader(pbuf.Bytes()), int64(pbuf.Len()))
				if err != nil {
					return err
				}
				var cnames []string
				for _, file := range cr.Files {
					cnames = append(cnames, file.Name)
				}
				sort.StringSlice(cnames).Sort()
				for _, name := range cnames {
					fmt.Println(name)
				}
			}
		}

		return nil
	},
}
