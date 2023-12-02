/*
Copyright © 2018-2023 blacktop

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
package idev

import (
	"fmt"
	"io"
	"os"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/usb/afc"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	AfcCmd.AddCommand(idevAfcCatCmd)

}

// idevAfcCatCmd represents the cat command
var idevAfcCatCmd = &cobra.Command{
	Use:           "cat",
	Short:         "cat file rooted at /var/mobile/Media",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		udid, _ := cmd.Flags().GetString("udid")

		if len(udid) == 0 {
			dev, err := utils.PickDevice()
			if err != nil {
				return fmt.Errorf("failed to pick USB connected devices: %w", err)
			}
			udid = dev.UniqueDeviceID
		}

		cli, err := afc.NewClient(udid)
		if err != nil {
			return fmt.Errorf("failed to connect to afc: %w", err)
		}
		defer cli.Close()

		finfo, err := cli.GetFileInfo(args[0])
		if err != nil {
			return fmt.Errorf("failed to get file info: %w", err)
		}

		if finfo.IsDir() {
			return fmt.Errorf("%s is a directory", args[0])
		}

		f, err := cli.FileRefOpen(args[0], os.O_RDONLY)
		if err != nil {
			return fmt.Errorf("failed to open file: %w", err)
		}
		defer f.Close()

		if _, err := io.Copy(os.Stdout, f); err != nil {
			return fmt.Errorf("failed to cat file: %w", err)
		}

		return nil
	},
}
