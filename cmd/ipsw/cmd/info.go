/*
Copyright © 2020 blacktop

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
	"os"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(infoCmd)

	infoCmd.Flags().BoolVarP(&remoteFlag, "remote", "r", false, "Extract from URL")
	infoCmd.MarkZshCompPositionalArgumentFile(1, "*ipsw")
}

// infoCmd represents the info command
var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Display IPSW Info",
	Long:  longDesc,
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if Verbose {
			log.SetLevel(log.DebugLevel)
		}
		if remoteFlag {
			pIPSW, err := info.RemoteParse(args[0])
			if err != nil {
				return errors.Wrap(err, "failed to extract remote plists")
			}
			fmt.Println(pIPSW)
		} else {
			if _, err := os.Stat(args[0]); os.IsNotExist(err) {
				return fmt.Errorf("file %s does not exist", args[0])
			}
			pIPSW, err := info.Parse(args[0])
			if err != nil {
				return errors.Wrap(err, "failed to extract and parse IPSW info")
			}
			fmt.Println(pIPSW)
		}
		return nil
	},
}
