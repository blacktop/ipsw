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
package ssh

import (
	"fmt"
	"path/filepath"
	"runtime"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/ssh"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const standardDebugserver = "/usr/libexec/debugserver" // NEW location in FS cryptex on device

func init() {
	SSHCmd.AddCommand(sshDebugserverCmd)

	sshDebugserverCmd.Flags().BoolP("force", "f", false, "overwrite file on device")
	sshDebugserverCmd.Flags().StringP("image", "m", "", "path to DeveloperDiskImage.dmg")
	sshDebugserverCmd.Flags().StringP("dest", "d", "/usr/libexec", "destination directory on device")
	viper.BindPFlag("ssh.debugserver.force", sshDebugserverCmd.Flags().Lookup("force"))
	viper.BindPFlag("ssh.debugserver.image", sshDebugserverCmd.Flags().Lookup("image"))
	viper.BindPFlag("ssh.debugserver.dest", sshDebugserverCmd.Flags().Lookup("dest"))
}

// sshDebugserverCmd represents the debugserver command
var sshDebugserverCmd = &cobra.Command{
	Use:           "debugserver",
	Aliases:       []string{"ds"},
	Short:         "Prepare device for remote debugging",
	Args:          cobra.NoArgs,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		// parent flags
		viper.BindPFlag("ssh.host", cmd.Flags().Lookup("host"))
		viper.BindPFlag("ssh.port", cmd.Flags().Lookup("port"))
		viper.BindPFlag("ssh.user", cmd.Flags().Lookup("user"))
		viper.BindPFlag("ssh.password", cmd.Flags().Lookup("password"))
		viper.BindPFlag("ssh.key", cmd.Flags().Lookup("key"))
		viper.BindPFlag("ssh.insecure", cmd.Flags().Lookup("insecure"))

		// Always check standard locations, but copy to user-specified destination
		destDebugserver := filepath.Join(viper.GetString("ssh.debugserver.dest"), "debugserver")

		log.Infof("Connecting to %s@%s:%s", viper.GetString("ssh.user"), viper.GetString("ssh.host"), viper.GetString("ssh.port"))
		cli, err := ssh.NewSSH(&ssh.Config{
			Host:     viper.GetString("ssh.host"),
			Port:     viper.GetString("ssh.port"),
			User:     viper.GetString("ssh.user"),
			Pass:     viper.GetString("ssh.password"),
			Key:      viper.GetString("ssh.key"),
			Insecure: viper.GetBool("ssh.insecure"),
		})
		if err != nil {
			return fmt.Errorf("failed to create ssh client: %w", err)
		}
		defer cli.Close()

		if cli.FileExists(standardDebugserver) {
			utils.Indent(log.Info, 2)(fmt.Sprintf("Copying '%s' from device to '/tmp/debugserver'", standardDebugserver))
			if err := cli.CopyFromDevice(standardDebugserver, "/tmp/debugserver"); err != nil {
				return err
			}

			utils.Indent(log.Info, 2)("Adding entitlements to '/tmp/debugserver'")
			if err := ssh.ResignDebugserver("/tmp/debugserver"); err != nil {
				return fmt.Errorf("failed to resign debugserver: %w", err)
			}

			utils.Indent(log.Info, 2)(fmt.Sprintf("Copying '/tmp/debugserver' back to device at '%s'", destDebugserver))
			if err := cli.CopyToDevice("/tmp/debugserver", destDebugserver); err != nil {
				return fmt.Errorf("failed to copy debugserver to device: %w", err)
			}

			utils.Indent(log.Info, 2)(fmt.Sprintf("Running 'chmod 0755 %s' on device", destDebugserver))
			if err := cli.RunCommand(fmt.Sprintf("chmod 0755 %s", destDebugserver)); err != nil {
				return fmt.Errorf("failed to chmod %s on device: %w", destDebugserver, err)
			}
		} else if cli.FileExists("/usr/bin/debugserver") || viper.GetBool("ssh.debugserver.force") { // OLD location from DDI mount
			if runtime.GOOS != "darwin" {
				return fmt.Errorf("attempting to extract debugserver from DeveloperDiskImage in Xcode.app on non-darwin system (not currently supported)")
			}
			// Find all the DeveloperDiskImages
			images, err := filepath.Glob("/Applications/Xcode*.app/Contents/Developer/Platforms/iPhoneOS.platform/DeviceSupport/*/DeveloperDiskImage.dmg")
			if err != nil {
				return fmt.Errorf("failed to glob for DeveloperDiskImage.dmg (in Xcode.app): %w", err)
			}

			imagePath := viper.GetString("ssh.debugserver.image")

			if len(imagePath) == 0 {
				choice := 0
				prompt := &survey.Select{
					Message: "Select the DeveloperDiskImage you want to extract the debugserver from:",
					Options: images,
				}
				if err := survey.AskOne(prompt, &choice); err == terminal.InterruptErr {
					log.Warn("Exiting...")
					return nil
				}
				imagePath = images[choice]
			}

			utils.Indent(log.Info, 2)("Mounting DeveloperDiskImage")
			mountPoint := "/tmp/dev_img"
			if err := utils.Mount(imagePath, mountPoint); err != nil {
				utils.Indent(log.Fatal, 2)(fmt.Sprintf("failed to mount %s: %v", imagePath, err))
			}
			defer func() {
				utils.Indent(log.Info, 2)("Unmounting DeveloperDiskImage")
				if err := utils.Retry(3, 2*time.Second, func() error {
					return utils.Unmount(mountPoint, false)
				}); err != nil {
					log.Errorf("failed to unmount %s at %s: %v", imagePath, mountPoint, err)
				}
			}()

			utils.Indent(log.Info, 2)("Copy debugserver from mounted DDI to '/tmp/debugserver'")
			if err := utils.Copy("/tmp/dev_img/usr/bin/debugserver", "/tmp/debugserver"); err != nil {
				return fmt.Errorf("failed to copy debugserver from DeveloperDiskImage: %w", err)
			}

			utils.Indent(log.Info, 2)("Adding entitlements to '/tmp/debugserver'")
			if err := ssh.ResignDebugserver("/tmp/debugserver"); err != nil {
				return fmt.Errorf("failed to resign debugserver: %w", err)
			}

			utils.Indent(log.Info, 2)(fmt.Sprintf("Copying '/tmp/debugserver' back to device at '%s'", destDebugserver))
			if err := cli.CopyToDevice("/tmp/debugserver", destDebugserver); err != nil {
				return fmt.Errorf("failed to copy debugserver to device: %w", err)
			}
			utils.Indent(log.Info, 2)(fmt.Sprintf("Running 'chmod 0755 %s' on device", destDebugserver))
			if err := cli.RunCommand(fmt.Sprintf("chmod 0755 %s", destDebugserver)); err != nil {
				return fmt.Errorf("failed to chmod %s on device: %w", destDebugserver, err)
			}
		} else {
			log.Warn("debugserver already on device")
		}

		utils.Indent(log.Info, 2)("Enabling private data in logs")
		if err := cli.EnablePrivateLogData(); err != nil {
			return fmt.Errorf("failed to enable private data in logs: %w", err)
		}

		utils.Indent(log.Info, 2)("Enabling symbolication of mobile crash logs")
		if err := cli.EnableSymbolication(); err != nil {
			return fmt.Errorf("failed to enable symbolication of mobile crash logs: %w", err)
		}
		/*
		 * killall logd
		 */
		utils.Indent(log.Info, 2)("Restarting logd")
		if err := cli.RunCommand("killall logd"); err != nil {
			return fmt.Errorf("failed to restart logd: %w", err)
		}

		return nil
	},
}
