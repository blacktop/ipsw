/*
Copyright © 2018-2024 blacktop

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
	"errors"
	"fmt"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/usb/amfi"
	"github.com/blacktop/ipsw/pkg/usb/heartbeat"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	AmfiCmd.AddCommand(idevAmfiDevModeCmd)

	idevAmfiDevModeCmd.Flags().BoolP("post", "p", false, "Enable post restart (acknowledges prompt after reboot)")
}

// idevAmfiDevModeCmd represents the push command
var idevAmfiDevModeCmd = &cobra.Command{
	Use:           "dev",
	Aliases:       []string{"d", "developer", "developer-mode"},
	Short:         "Enabled Developer Mode on device",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) (err error) {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")
		// flags
		udid, _ := cmd.Flags().GetString("udid")
		postRestart, _ := cmd.Flags().GetBool("post")

		if len(udid) == 0 {
			dev, err := utils.PickDevice()
			if err != nil {
				return fmt.Errorf("failed to pick USB connected devices: %w", err)
			}
			udid = dev.UniqueDeviceID
		}

		ok, err := utils.IsDeveloperModeEnabled(udid)
		if err != nil {
			return fmt.Errorf("failed to check if Developer Mode is enabled for device %s: %w", udid, err)
		}

		if ok {
			log.Infof("Developer Mode is already enabled for device %s", udid)
			return nil
		} else {
			cli, err := amfi.NewClient(udid)
			if err != nil {
				return fmt.Errorf("failed to connect to amfi: %w", err)
			}
			defer cli.Close()

			if err := cli.EnableDeveloperMode(); err != nil {
				if errors.Is(err, amfi.ErrPasscodeSet) {
					return fmt.Errorf("cannot enabled Developer Mode when a pass-code is set: %w", err)
				} else {
					return fmt.Errorf("failed to enable Developer Mode: %w", err)
				}
			}

			if postRestart {
				awake := make(chan bool)
				defer close(awake)
				errs := make(chan error)
				defer close(errs)

				log.Warn("Waiting for device to reboot...")

				go func() {
					rebooting := false
					for {
						hb, err := heartbeat.NewClient(udid)
						if err != nil {
							log.Debugf("failed to connect to heartbeat: %v", err)
							rebooting = true
							time.Sleep(1 * time.Second)
							continue // ignore heartbeat connection errors (device may be rebooting)
						}
						beat, err := hb.Beat()
						if err != nil {
							errs <- fmt.Errorf("failed to start heartbeat: %w", err)
						}
						if rebooting && beat.Command == "Marco" { // REBOOTED
							awake <- true
							break
						}
						hb.Close()
						time.Sleep(1 * time.Second)
					}
				}()

				select {
				case err := <-errs:
					return err
				case <-awake:
					cli, err := amfi.NewClient(udid)
					if err != nil {
						return fmt.Errorf("failed to connect to amfi: %w", err)
					}
					defer cli.Close()
					if err := cli.EnableDeveloperModePostRestart(); err != nil {
						return fmt.Errorf("failed to enable Developer Mode post restart: %w", err)
					}
					return nil
				case <-time.After(time.Minute):
					return fmt.Errorf("device did not restart in time (1 minute)")
				}
			}

			return nil
		}
	},
}
