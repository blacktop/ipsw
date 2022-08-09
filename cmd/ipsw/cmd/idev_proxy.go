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
package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/usb/forward"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
	"github.com/spf13/cobra"
)

func init() {
	idevCmd.AddCommand(iDevProxyCmd)

	iDevProxyCmd.Flags().IntP("lport", "l", 0, "host port")
	iDevProxyCmd.Flags().IntP("rport", "r", 0, "device port")
}

// iDevProxyCmd represents the proxy command
var iDevProxyCmd = &cobra.Command{
	Use:           "proxy",
	Short:         "Create a TCP proxy (for ssh/debugging)",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		uuid, _ := cmd.Flags().GetString("uuid")
		lport, _ := cmd.Flags().GetInt("lport")
		rport, _ := cmd.Flags().GetInt("rport")

		var err error
		var dev *lockdownd.DeviceValues
		if len(uuid) == 0 {
			dev, err = utils.PickDevice()
			if err != nil {
				return fmt.Errorf("failed to pick USB connected devices: %w", err)
			}
		} else {
			ldc, err := lockdownd.NewClient(uuid)
			if err != nil {
				return fmt.Errorf("failed to connect to lockdownd: %w", err)
			}
			defer ldc.Close()

			dev, err = ldc.GetValues()
			if err != nil {
				return fmt.Errorf("failed to get device values for %s: %w", uuid, err)
			}
		}

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGABRT)
		defer cancel()

		log.WithFields(log.Fields{
			"lport": lport,
			"rport": rport,
		}).Info("Connecting proxy to device")
		if err := forward.Start(ctx, dev.UniqueDeviceID, lport, rport, func(s string, err error) {
			if err != nil {
				log.Fatalf(err.Error())
			}
		}); err != nil {
			return err
		}

		<-ctx.Done()

		return nil
	},
}
