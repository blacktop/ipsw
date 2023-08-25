/*
Copyright © 2023 blacktop

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
	"encoding/json"
	"fmt"
	"os"

	"github.com/alecthomas/chroma/v2/quick"
	"github.com/apex/log"
	"github.com/blacktop/go-plist"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(plistCmd)

	// plistCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	// viper.BindPFlag("plist.json", diffCmd.Flags().Lookup("json"))
}

// plistCmd represents the pl command
var plistCmd = &cobra.Command{
	Use:     "plist",
	Aliases: []string{"pl"},
	Short:   "Dump plist as JSON",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		data, err := os.ReadFile(args[0])
		if err != nil {
			return fmt.Errorf("failed to read plist: %v", err)
		}

		var out map[string]any
		if err := plist.NewDecoder(bytes.NewReader(data)).Decode(&out); err != nil {
			return fmt.Errorf("failed to decode plist: %v", err)
		}

		jsonData, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal json: %v", err)
		}

		if viper.GetBool("color") {
			if err := quick.Highlight(os.Stdout, string(jsonData)+"\n", "json", "terminal256", "nord"); err != nil {
				return fmt.Errorf("failed to highlight json: %v", err)
			}
		} else {
			fmt.Println(string(jsonData))
		}

		return nil
	},
}
