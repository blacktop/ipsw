//go:build cgo

/*
Copyright © 2018-2022 blacktop

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
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/spf13/cobra"
)

func init() {
	kernelcacheCmd.AddCommand(sbdecCmd)
	sbdecCmd.Flags().BoolP("dump", "d", false, "Dump sandbox profile data")
	sbdecCmd.MarkZshCompPositionalArgumentFile(1, "kernelcache*")
}

// sbdecCmd represents the kernel sbdec command
var sbdecCmd = &cobra.Command{
	Use:           "sbdec",
	Short:         "🚧 [WIP] Decompile Sandbox Profile",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	Hidden:        true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		dump, _ := cmd.Flags().GetBool("dump")

		kcPath := filepath.Clean(args[0])

		if _, err := os.Stat(kcPath); os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", args[0])
		}

		m, err := macho.Open(kcPath)
		if err != nil {
			return err
		}
		defer m.Close()

		sb, err := kernelcache.NewSandbox(m)
		if err != nil {
			return err
		}

		if dump {
			if dat, err := sb.GetPlatformProfileData(); err != nil {
				return fmt.Errorf("failed to get sandbox platform profile data: %v", err)
			} else {
				sbppath := filepath.Join(filepath.Dir(kcPath), "sandbox_profile.bin")
				log.Infof("Creating %s...", sbppath)
				if err := ioutil.WriteFile(sbppath, dat, 0755); err != nil {
					return fmt.Errorf("failed to write sandbox platform profile data: %v", err)
				}
			}
			if dat, err := sb.GetCollectionData(); err != nil {
				return fmt.Errorf("failed to get sandbox collection data: %v", err)
			} else {
				sbcpath := filepath.Join(filepath.Dir(kcPath), "sandbox_collection.bin")
				log.Infof("Creating %s...", sbcpath)
				if err := ioutil.WriteFile(sbcpath, dat, 0755); err != nil {
					return fmt.Errorf("failed to write sandbox collection data: %v", err)
				}
			}
		}

		if err := sb.ParseSandboxCollection(); err != nil {
			return fmt.Errorf("failed parsing sandbox collection: %s", err)
		}

		// regexFolder := filepath.Join(filepath.Dir(kcPath), "regex")
		// os.MkdirAll(regexFolder, 0755)

		// for off, data := range sb.Regexes {
		// 	regexPath := filepath.Join(regexFolder, fmt.Sprintf("regex_%x", off))
		// 	err = ioutil.WriteFile(regexPath, data, 0755)
		// 	if err != nil {
		// 		return err
		// 	}
		// }

		return nil
	},
}
