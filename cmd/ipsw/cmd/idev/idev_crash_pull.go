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
	"io/fs"
	"os"
	"path/filepath"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/usb/crashlog"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	CrashCmd.AddCommand(iDevCrashPullCmd)
	iDevCrashPullCmd.Flags().BoolP("all", "a", false, "Pull all crashlogs")
	iDevCrashPullCmd.Flags().BoolP("rm", "r", false, "Remove crashlogs after pulling")
	iDevCrashPullCmd.Flags().StringP("output", "o", "", "Folder to save crashlogs")
	iDevCrashPullCmd.MarkFlagDirname("output")
}

// iDevCrashPullCmd represents the pull command
var iDevCrashPullCmd = &cobra.Command{
	Use:           "pull",
	Short:         "Pull crashlogs",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		udid, _ := cmd.Flags().GetString("udid")
		output, _ := cmd.Flags().GetString("output")
		allLogs, _ := cmd.Flags().GetBool("all")
		removeLogs, _ := cmd.Flags().GetBool("rm")

		var err error
		var dev *lockdownd.DeviceValues
		if len(udid) == 0 {
			dev, err = utils.PickDevice()
			if err != nil {
				return fmt.Errorf("failed to pick USB connected devices: %w", err)
			}
		} else {
			ldc, err := lockdownd.NewClient(udid)
			if err != nil {
				return fmt.Errorf("failed to connect to lockdownd: %w", err)
			}
			dev, err = ldc.GetValues()
			if err != nil {
				return fmt.Errorf("failed to get device values for %s: %w", udid, err)
			}
			ldc.Close()
		}

		cli, err := crashlog.NewClient(dev.UniqueDeviceID)
		if err != nil {
			return fmt.Errorf("failed to connect to crashlog service: %w", err)
		}
		defer cli.Close()

		if allLogs { // pull all crashlogs
			destPath := filepath.Join(output, fmt.Sprintf("%s_%s_%s", dev.ProductType, dev.HardwareModel, dev.BuildVersion))
			if err := cli.CopyFromDevice(destPath, "/", nil); err != nil {
				return fmt.Errorf("failed to copy all crashlogs from device: %w", err)
			}
			if removeLogs {
				if err := cli.RemoveAll("/"); err != nil {
					return fmt.Errorf("failed to remove all crashlogs from device: %w", err)
				}
			}
		} else if len(args) == 0 { // list logs for user selection
			var logs []string
			if err := cli.Walk("/", func(path string, info fs.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() {
					return nil
				}
				logs = append(logs, path)
				return nil
			}); err != nil {
				return fmt.Errorf("failed to list crashlogs: %w", err)
			}

			choices := []int{}
			prompt := &survey.MultiSelect{
				Message:  "Choose crashlog(s):",
				Options:  logs,
				PageSize: 50,
			}
			if err := survey.AskOne(prompt, &choices, survey.WithKeepFilter(true)); err != nil {
				if err == terminal.InterruptErr {
					log.Warn("Exiting...")
					os.Exit(0)
				}
				return err
			}
			var chosenLogs []string
			for _, idx := range choices {
				chosenLogs = append(chosenLogs, logs[idx])
			}

			for _, clog := range chosenLogs {
				destPath := filepath.Join(output, fmt.Sprintf("%s_%s_%s", dev.ProductType, dev.HardwareModel, dev.BuildVersion), clog)
				if err := os.MkdirAll(filepath.Dir(destPath), 0750); err != nil {
					return fmt.Errorf("failed to create destination directory: %w", err)
				}
				log.WithFields(log.Fields{
					"log": destPath,
				}).Info("Pulling")
				if err := cli.CopyFileFromDevice(destPath, clog); err != nil {
					return fmt.Errorf("failed to copy crashlog from device: %w", err)
				}
				if removeLogs {
					if err := cli.RemovePath(clog); err != nil {
						return fmt.Errorf("failed to remove crashlog from device: %w", err)
					}
				}
			}
		} else { // pull specific crashlogs
			destPath := filepath.Join(output, fmt.Sprintf("%s_%s_%s", dev.ProductType, dev.HardwareModel, dev.BuildVersion), args[0])
			if err := os.MkdirAll(filepath.Dir(destPath), 0750); err != nil {
				return fmt.Errorf("failed to create destination directory: %w", err)
			}
			log.WithFields(log.Fields{
				"log": destPath,
			}).Info("Pulling")
			if err := cli.CopyFileFromDevice(destPath, args[0]); err != nil {
				return fmt.Errorf("failed to copy crashlog from device: %w", err)
			}
			if removeLogs {
				if err := cli.RemovePath(args[0]); err != nil {
					return fmt.Errorf("failed to remove crashlog from device: %w", err)
				}
			}
		}

		return nil
	},
}
