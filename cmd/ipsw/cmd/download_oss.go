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
	"encoding/json"
	"fmt"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/spf13/cobra"
)

func init() {
	downloadCmd.AddCommand(ossCmd)

	// devCmd.Flags().StringP("macos", "m", viper.GetString("IPSW_OSS_MACOS_VERSION"), "macOS version to download")
}

// ossCmd represents the oss command
var ossCmd = &cobra.Command{
	Use:   "oss <macOS version>",
	Short: "Download opensource.apple.com file list for macOS version",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		proxy, _ := cmd.Flags().GetString("proxy")
		insecure, _ := cmd.Flags().GetBool("insecure")

		// macOS, _ := cmd.Flags().GetString("macos")

		o, err := download.NewOSS(strings.Replace(args[0], ".", "", -1), proxy, insecure)
		if err != nil {
			log.Fatal(err.Error())
		}

		if dat, err := json.MarshalIndent(o, "", "   "); err == nil {
			fmt.Println(string(dat))
		} else {
			log.Fatal(err.Error())
		}
	},
}
