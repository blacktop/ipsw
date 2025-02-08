/*
Copyright © 2018-2025 blacktop

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
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/blacktop/ipsw/internal/download"
	"github.com/spf13/cobra"
)

// keyListGenCmd represents the key-list-gen command
var keyListGenCmd = &cobra.Command{
	Use:    "key-list-gen",
	Short:  "Generate iOS firmware key database",
	Args:   cobra.MinimumNArgs(1),
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		keys, err := download.ScrapeKeys("")
		if err != nil {
			return err
		}

		keysJSON, err := json.Marshal(keys)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Clean(args[0]), keysJSON, 0660)
	},
}

func init() {
	rootCmd.AddCommand(keyListGenCmd)
}
