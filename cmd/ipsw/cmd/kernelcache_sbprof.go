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
	"bytes"
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
	kernelcacheCmd.AddCommand(sbprofCmd)

	sbprofCmd.MarkZshCompPositionalArgumentFile(1, "kernelcache*")
}

// sbprofCmd represents the sbprof command
var sbprofCmd = &cobra.Command{
	Use:    "sbprof",
	Short:  "🚧 [WIP] Extract kernel sandbox profile data",
	Args:   cobra.MinimumNArgs(1),
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		kcPath := filepath.Clean(args[0])

		if _, err := os.Stat(kcPath); os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", args[0])
		}

		m, err := macho.Open(kcPath)
		if err != nil {
			return err
		}
		defer m.Close()

		data, err := ioutil.ReadFile(kcPath)
		if err != nil {
			return err
		}

		sbProfData, err := kernelcache.GetSandboxProfiles(m, bytes.NewReader(data))
		if err != nil {
			return err
		}

		err = ioutil.WriteFile(filepath.Join(filepath.Dir(kcPath), "sandbox_profile.bin"), sbProfData, 0755)
		if err != nil {
			return err
		}

		return nil
	},
}
