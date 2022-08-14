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
package kernel

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	KernelcacheCmd.AddCommand(kerExtractCmd)

	kerExtractCmd.MarkZshCompPositionalArgumentFile(1, "*.ipsw")
}

// kerExtractCmd represents the kerExtract command
var kerExtractCmd = &cobra.Command{
	Use:   "extract <IPSW> [DEST]",
	Short: "Extract and decompress a kernelcache from IPSW",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		ipswPath := filepath.Clean(args[0])

		var destPath string
		if len(args) > 1 {
			destPath = filepath.Clean(args[1])
		}

		if _, err := os.Stat(ipswPath); os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", ipswPath)
		}

		i, err := info.Parse(ipswPath)
		if err != nil {
			return fmt.Errorf("failed to parse ipsw info: %v", err)
		}

		folder, err := i.GetFolder()
		if err != nil {
			log.Errorf("failed to get IPSW spec folder: %v", err)
		}
		destPath = filepath.Join(destPath, folder)

		log.Info("Extracting kernelcaches")
		return kernelcache.Extract(ipswPath, destPath)
	},
}
