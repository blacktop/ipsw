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
	"context"
	"errors"
	"fmt"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/usb/notification"
	"github.com/caarlos0/ctrlc"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	IDevCmd.AddCommand(NotificationCmd)

	NotificationCmd.Flags().StringP("notification", "n", "", "notification to observe")
	NotificationCmd.Flags().BoolP("all", "a", false, "observe all notifications")
}

// NotificationCmd represents the noti command
var NotificationCmd = &cobra.Command{
	Use:           "noti",
	Short:         "Observe notifications",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		udid, _ := cmd.Flags().GetString("udid")
		notificationName, _ := cmd.Flags().GetString("notification")
		all, _ := cmd.Flags().GetBool("all")

		if len(udid) == 0 {
			dev, err := utils.PickDevice()
			if err != nil {
				return fmt.Errorf("failed to pick USB connected devices: %w", err)
			}
			udid = dev.UniqueDeviceID
		}

		cli, err := notification.NewClient(udid)
		if err != nil {
			return fmt.Errorf("failed to connect to notification service: %w", err)
		}
		defer cli.Close()

		if all {
			if err := cli.ObserveAllNotifications(); err != nil {
				return fmt.Errorf("failed to observe all notification: %w", err)
			}
		} else {
			if err := cli.ObserveNotification(notificationName); err != nil {
				return fmt.Errorf("failed to observe notification: %w", err)
			}
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if err := ctrlc.Default.Run(ctx, func() error {
			if err := cli.Listen(ctx); err != nil {
				return fmt.Errorf("failed to listen for notifications: %w", err)
			}
			return nil
		}); err != nil {
			if errors.As(err, &ctrlc.ErrorCtrlC{}) {
				log.Warn("Exiting...")
			} else {
				return err
			}
		}

		return nil
	},
}
