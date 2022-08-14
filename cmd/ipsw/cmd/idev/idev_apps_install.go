/*
Copyright © 2022 blacktop

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
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/usb/apps"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vbauerster/mpb/v7"
	"github.com/vbauerster/mpb/v7/decor"
)

func init() {
	AppsCmd.AddCommand(idevAppsInstallCmd)
}

// idevAppsInstallCmd represents the install command
var idevAppsInstallCmd = &cobra.Command{
	Use:           "install <IPA_PATH>",
	Short:         "Install an application",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		udid, _ := cmd.Flags().GetString("udid")
		ipaPath := filepath.Clean(args[0])

		if len(udid) == 0 {
			dev, err := utils.PickDevice()
			if err != nil {
				return fmt.Errorf("failed to pick USB connected devices: %w", err)
			}
			udid = dev.UniqueDeviceID
		}

		cli, err := apps.NewClient(udid)
		if err != nil {
			return fmt.Errorf("failed to connect to apps client: %w", err)
		}
		defer cli.Close()

		// initialize progress bar
		p := mpb.New(mpb.WithWidth(80))
		// adding a single bar, which will inherit container's width
		name := "Installing"
		bar := p.New(100,
			// progress bar filler with customized style
			mpb.BarStyle().Lbound("[").Filler("=").Tip(">").Padding("-").Rbound("|"),
			mpb.PrependDecorators(
				decor.Name(name, decor.WC{W: len(name) + 1, C: decor.DidentRight}),
				// replace ETA decorator with "done" message, OnComplete event
				decor.OnComplete(
					decor.AverageETA(decor.ET_STYLE_GO, decor.WC{W: 4}), "✅ ",
				),
			),
			mpb.AppendDecorators(
				decor.Percentage(),
				decor.Name(" ] "),
			),
		)

		if err := cli.CopyAndInstall(ipaPath, func(progress *apps.ProgressEvent) {
			bar.SetCurrent(int64(progress.PercentComplete))
		}); err != nil {
			return fmt.Errorf("failed to copy and install %s: %w", ipaPath, err)
		}

		// wait for our bar to complete and flush
		p.Wait()

		return nil
	},
}
