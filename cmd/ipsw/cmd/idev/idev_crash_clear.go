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
	"io/fs"

	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/usb/crashlog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	CrashCmd.AddCommand(iDevCrashClearCmd)

}

// iDevCrashClearCmd represents the clear command
var iDevCrashClearCmd = &cobra.Command{
	Use:           "clear",
	Short:         "Delete all crashlogs",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		udid, _ := cmd.Flags().GetString("udid")

		if len(udid) == 0 {
			dev, err := utils.PickDevice()
			if err != nil {
				return fmt.Errorf("failed to pick USB connected devices: %w", err)
			}
			udid = dev.UniqueDeviceID
		}

		cli, err := crashlog.NewClient(udid)
		if err != nil {
			return fmt.Errorf("failed to connect to crashlog service: %w", err)
		}
		defer cli.Close()

		yes := false
		prompt := &survey.Confirm{
			Message: "Are you sure you want to delete ALL the crashlogs?",
		}
		survey.AskOne(prompt, &yes)

		if yes {
			if err := cli.RemoveAll("/"); err != nil {
				log.Errorf("failed to remove all crashlogs from device: %v", err)
				if err := cli.Walk("/", func(path string, info fs.FileInfo, err error) error {
					if err != nil {
						return err
					}
					if info.IsDir() {
						return nil
					}
					utils.Indent(log.Error, 2)(path)
					return nil
				}); err != nil {
					log.Errorf("failed to list crashlogs: %v", err)
				}
			}
		}

		return nil
	},
}
