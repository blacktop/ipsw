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
package cmd

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func init() {
	rootCmd.AddCommand(debugserverCmd)
	debugserverCmd.Flags().StringP("host", "t", "localhost", "ssh host")
	debugserverCmd.Flags().StringP("port", "p", "2222", "ssh port")
	debugserverCmd.Flags().StringP("image", "i", "", "path to DeveloperDiskImage.dmg")
	debugserverCmd.Flags().BoolP("force", "f", false, "overwrite file on device")
	debugserverCmd.Flags().BoolP("insecure", "n", false, "ignore known_hosts key checking")
	viper.BindPFlag("debugserver.host", debugserverCmd.Flags().Lookup("host"))
	viper.BindPFlag("debugserver.port", debugserverCmd.Flags().Lookup("port"))
	viper.BindPFlag("debugserver.image", debugserverCmd.Flags().Lookup("image"))
	viper.BindPFlag("debugserver.force", debugserverCmd.Flags().Lookup("force"))
	viper.BindPFlag("debugserver.insecure", debugserverCmd.Flags().Lookup("insecure"))
}

var (
	//go:embed data/debugserver.plist
	entitlementsData []byte
	//go:embed data/com.apple.system.logging.plist
	loggingPlistData []byte
	//go:embed data/com.apple.CrashReporter.plist
	symbolicationPlistData []byte
)

// debugserverCmd represents the debugserver command
var debugserverCmd = &cobra.Command{
	Use:           "debugserver",
	Aliases:       []string{"ds"},
	Short:         "Prep device for remote debugging",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		sshHost, _ := cmd.Flags().GetString("host")
		sshPort, _ := cmd.Flags().GetString("port")
		imagePath, _ := cmd.Flags().GetString("image")
		force, _ := cmd.Flags().GetBool("force")
		insecure, _ := cmd.Flags().GetBool("force")

		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get user home directory: %w", err)
		}

		var sshConfig *ssh.ClientConfig
		if insecure {
			sshConfig = &ssh.ClientConfig{
				User: "root",
				Auth: []ssh.AuthMethod{
					ssh.Password("alpine"),
				},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			}
		} else {
			hostKeyCallback, err := knownhosts.New(filepath.Join(home, ".ssh/known_hosts"))
			if err != nil {
				return fmt.Errorf("failed to create ssh host key callback: %w", err)
			}
			sshConfig = &ssh.ClientConfig{
				User: "root",
				Auth: []ssh.AuthMethod{
					ssh.Password("alpine"),
				},
				HostKeyCallback: hostKeyCallback,
			}
		}

		utils.Indent(log.Info, 1)(fmt.Sprintf("Connecting to root@%s:%s", sshHost, sshPort))

		client, err := ssh.Dial("tcp", sshHost+":"+sshPort, sshConfig)
		if err != nil {
			log.Fatalf("failed to dial: %s", err)
		}

		session, err := client.NewSession()
		if err != nil {
			log.Fatalf("failed to create session: %s", err)
		}
		defer session.Close()

		output, _ := session.CombinedOutput("/bin/ls /usr/bin/debugserver")
		// if err != nil {
		// 	log.Error(string(output))
		// }

		if strings.Contains(string(output), "No such file or directory") || force {
			// Find all the DeveloperDiskImages
			images, err := filepath.Glob("/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/DeviceSupport/*/DeveloperDiskImage.dmg")
			if err != nil {
				return fmt.Errorf("failed to glob for DeveloperDiskImage.dmg: %w", err)
			}
			betaImages, err := filepath.Glob("/Applications/Xcode-beta.app/Contents/Developer/Platforms/iPhoneOS.platform/DeviceSupport/*/DeveloperDiskImage.dmg")
			if err != nil {
				return fmt.Errorf("failed to glob for beta DeveloperDiskImage.dmg: %w", err)
			}

			images = append(images, betaImages...)

			if len(imagePath) == 0 {
				choice := 0
				prompt := &survey.Select{
					Message: "Select the DeveloperDiskImage you want to extract the debugserver from:",
					Options: images,
				}
				survey.AskOne(prompt, &choice)
				imagePath = images[choice]
			}

			utils.Indent(log.Info, 2)("Mounting DeveloperDiskImage")
			if err := utils.Mount(imagePath, "/tmp/dev_img"); err != nil {
				utils.Indent(log.Fatal, 2)(fmt.Sprintf("failed to mount %s: %v", imagePath, err))
			}
			defer func() {
				utils.Indent(log.Info, 2)("Unmounting DeveloperDiskImage")
				if err := utils.Unmount("/tmp/dev_img", false); err != nil {
					utils.Indent(log.Fatal, 2)(fmt.Sprintf("failed to unmount /tmp/dev_img: %v", err))
				}
			}()

			// Read entitlements.plist and write to tmp file
			tmpEntsFile, err := os.CreateTemp("", "entitlements.plist")
			if err != nil {
				return fmt.Errorf("failed to create tmp entitlements file: %w", err)
			}
			defer os.Remove(tmpEntsFile.Name()) // clean up
			if _, err := tmpEntsFile.Write(entitlementsData); err != nil {
				return fmt.Errorf("failed to write entitlements data to tmp file: %w", err)
			}
			if err := tmpEntsFile.Close(); err != nil {
				return fmt.Errorf("failed to close tmp entitlements file: %w", err)
			}

			// Read debugserver and write to tmp file
			roDbgSvr, err := os.Open("/tmp/dev_img/usr/bin/debugserver")
			if err != nil {
				return fmt.Errorf("failed to open debugserver: %w", err)
			}
			defer roDbgSvr.Close()
			tmpDbgSrvFile, err := os.CreateTemp("", "debugserver")
			if err != nil {
				return fmt.Errorf("failed to create tmp debugserver file: %w", err)
			}
			defer os.Remove(tmpDbgSrvFile.Name()) // clean up
			if _, err := io.Copy(tmpDbgSrvFile, roDbgSvr); err != nil {
				return fmt.Errorf("failed to copy debugserver to tmp file: %w", err)
			}
			if err := tmpDbgSrvFile.Close(); err != nil {
				return fmt.Errorf("failed to close tmp debugserver file: %w", err)
			}

			utils.Indent(log.Info, 2)("Adding entitlements to /usr/bin/debugserver")
			if err := utils.CodeSignWithEntitlements(tmpDbgSrvFile.Name(), tmpEntsFile.Name(), "-"); err != nil {
				return fmt.Errorf("failed to codesign debugserver with entitlements: %w", err)
			}

			utils.Indent(log.Info, 2)("Copying /usr/bin/debugserver to device")
			dbgSvr, err := os.Open(tmpDbgSrvFile.Name())
			if err != nil {
				return fmt.Errorf("failed to open debugserver: %w", err)
			}
			defer dbgSvr.Close()

			sessionSCP, err := client.NewSession()
			if err != nil {
				return fmt.Errorf("failed to create scp session: %v", err)
			}
			defer sessionSCP.Close()

			go func() error {
				w, _ := sessionSCP.StdinPipe()
				defer w.Close()

				count, err := io.Copy(w, dbgSvr)
				if err != nil {
					return fmt.Errorf("failed to copy /usr/bin/debugserver to device: %w", err)
				}
				if count == 0 {
					return fmt.Errorf("%d bytes copied to device", count)
				}

				return nil
			}()

			if err := sessionSCP.Start("cat > /usr/bin/debugserver"); err != nil {
				return fmt.Errorf("failed to copy /usr/bin/debugserver to device: %w", err)
			}

			if err := sessionSCP.Wait(); err != nil {
				return fmt.Errorf("failed to copy /usr/bin/debugserver to device: %w", err)
			}

			// chmod /usr/bin/debugserver
			sessionCHMOD, err := client.NewSession()
			if err != nil {
				return fmt.Errorf("failed to create chmod session: %v", err)
			}
			defer sessionCHMOD.Close()
			if err := sessionCHMOD.Start("chmod 0755 /usr/bin/debugserver"); err != nil {
				return fmt.Errorf("failed to chmod /usr/bin/debugserver: %w", err)
			}

			if err := sessionCHMOD.Wait(); err != nil {
				return fmt.Errorf("failed to chmod /usr/bin/debugserver: %w", err)
			}

			// CREDIT: https://github.com/EthanArbuckle/unredact-private-os_logs
			utils.Indent(log.Info, 2)("Enabling private data in logs")

			sessionLogSCP, err := client.NewSession()
			if err != nil {
				log.Fatalf("failed to create scp session: %s", err)
			}
			defer sessionLogSCP.Close()

			go func() error {
				w, _ := sessionLogSCP.StdinPipe()
				defer w.Close()

				count, err := io.Copy(w, bytes.NewReader(loggingPlistData))
				if err != nil {
					return fmt.Errorf("failed to copy logging plist to device: %w", err)
				}
				if count == 0 {
					return fmt.Errorf("%d bytes copied to device", count)
				}

				return nil
			}()

			if err := sessionLogSCP.Start("cat > /Library/Preferences/Logging/com.apple.system.logging.plist"); err != nil {
				return fmt.Errorf("failed to start scp session: %s", err)
			}

			if err := sessionLogSCP.Wait(); err != nil {
				return fmt.Errorf("failed to copy logging plist to device: %s", err)
			}

			// CREDIT: https://github.com/dlevi309/ios-scripts
			utils.Indent(log.Info, 2)("Enabling symbolication of mobile crash logs")

			sessionSymSCP, err := client.NewSession()
			if err != nil {
				log.Fatalf("failed to create scp session: %s", err)
			}
			defer sessionSymSCP.Close()

			go func() error {
				w, _ := sessionSymSCP.StdinPipe()
				defer w.Close()

				count, err := io.Copy(w, bytes.NewReader(symbolicationPlistData))
				if err != nil {
					return fmt.Errorf("failed to copy symbolication plist to device: %s", err)
				}
				if count == 0 {
					return fmt.Errorf("%d bytes copied to device", count)
				}

				return nil
			}()

			if err := sessionSymSCP.Start("cat > /var/root/Library/Preferences/com.apple.CrashReporter.plist"); err != nil {
				return fmt.Errorf("failed to copy symbolication plist to device: %s", err)
			}
			if err := sessionSymSCP.Wait(); err != nil {
				return fmt.Errorf("failed to copy symbolication plist to device: %s", err)
			}

			/*
			 * killall logd
			 */
			utils.Indent(log.Info, 2)("Restarting logd")
			sessionKillAll, err := client.NewSession()
			if err != nil {
				return fmt.Errorf("failed to create killall session: %v", err)
			}
			defer sessionKillAll.Close()
			if err := sessionKillAll.Start("killall logd"); err != nil {
				return fmt.Errorf("failed to kill logd: %s", err)
			}
			if err := sessionKillAll.Wait(); err != nil {
				return fmt.Errorf("failed to kill logd: %s", err)
			}

		} else {
			log.Warn("debugserver already on device")
		}

		return nil
	},
}
