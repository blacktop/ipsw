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
package kernel

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	KernelcacheCmd.AddCommand(kernelDecCmd)
	kernelDecCmd.Flags().StringP("output", "o", "", "Output file")
	kernelDecCmd.MarkZshCompPositionalArgumentFile(1, "kernelcache*")
}

// kernelDecCmd represents the dec command
var kernelDecCmd = &cobra.Command{
	Use:           "dec <kernelcache>",
	Short:         "Decompress a kernelcache",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		outputDir, _ := cmd.Flags().GetString("output")

		kcpath := filepath.Clean(args[0])

		if _, err := os.Stat(kcpath); os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", kcpath)
		}

		isImg4, err := magic.IsImg4(kcpath)
		if err != nil {
			return fmt.Errorf("failed to check if kernelcache is img4: %w", err)
		}

		if isImg4 {
			log.Info("Decompressing KernelManagement kernelcache")
			return kernelcache.DecompressKernelManagement(kcpath, outputDir)
		}

		log.Info("Decompressing kernelcache")
		return kernelcache.Decompress(kcpath, outputDir)
	},
}
