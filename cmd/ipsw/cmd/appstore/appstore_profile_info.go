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
package appstore

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/alecthomas/chroma/v2/quick"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/colors"
	"github.com/fullsailor/pkcs7"
	"github.com/spf13/cobra"
)

func init() {
	ASProfileCmd.AddCommand(ASProfileInfoCmd)
}

// ASProfileInfoCmd represents the info command
var ASProfileInfoCmd = &cobra.Command{
	Use:           "info",
	Aliases:       []string{"i"},
	Short:         "Dump provisioning profile information",
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		data, err := os.ReadFile(args[0])
		if err != nil {
			return fmt.Errorf("read provisioning profile: %w", err)
		}
		if len(data) == 0 {
			return fmt.Errorf("provisioning profile file is empty")
		}

		p7, err := pkcs7.Parse(data)
		if err != nil {
			return fmt.Errorf("parse PKCS#7 data: %w", err)
		}

		if len(p7.Content) == 0 {
			return fmt.Errorf("no content found in PKCS#7 data")
		}

		var profile any
		if _, err := plist.Unmarshal(p7.Content, &profile); err != nil {
			return fmt.Errorf("unmarshal provisioning profile plist: %w", err)
		}

		jsonData, err := json.MarshalIndent(profile, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal json: %v", err)
		}

		if colors.Active() {
			if err := quick.Highlight(os.Stdout, string(jsonData)+"\n", "json", "terminal256", "nord"); err != nil {
				return fmt.Errorf("failed to highlight json: %v", err)
			}
		} else {
			fmt.Println(string(jsonData))
		}

		return nil
	},
}
