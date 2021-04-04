/*
Copyright © 2021 blacktop

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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func init() {
	rootCmd.AddCommand(debugserverCmd)
	debugserverCmd.Flags().StringP("host", "t", "localhost", "ssh host")
	debugserverCmd.Flags().StringP("port", "p", "2222", "ssh port")
	debugserverCmd.Flags().StringP("image", "i", "", "path to DeveloperDiskImage.dmg")
	debugserverCmd.Flags().BoolP("force", "f", false, "overwrite file on device")
}

var (
	//go:embed data/debugserver.plist
	entitlementsData []byte
	//go:embed data/com.apple.system.logging.plist
	loggingPlistData []byte
)

// debugserverCmd represents the debugserver command
var debugserverCmd = &cobra.Command{
	Use:          "debugserver",
	Short:        "Prep device for remote debugging",
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	Hidden:       true,
	Run: func(cmd *cobra.Command, args []string) {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		sshHost, _ := cmd.Flags().GetString("host")
		sshPort, _ := cmd.Flags().GetString("port")
		imagePath, _ := cmd.Flags().GetString("image")
		force, _ := cmd.Flags().GetBool("force")

		home, err := homedir.Dir()
		if err != nil {
			log.Error(err.Error())
			return
		}

		hostKeyCallback, err := knownhosts.New(filepath.Join(home, ".ssh/known_hosts"))
		if err != nil {
			log.Error(err.Error())
			return
		}

		sshConfig := &ssh.ClientConfig{
			User: "root",
			Auth: []ssh.AuthMethod{
				ssh.Password("alpine"),
			},
			HostKeyCallback: hostKeyCallback,
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
				log.Error(err.Error())
				return
			}
			betaImages, err := filepath.Glob("/Applications/Xcode-beta.app/Contents/Developer/Platforms/iPhoneOS.platform/DeviceSupport/*/DeveloperDiskImage.dmg")
			if err != nil {
				log.Error(err.Error())
				return
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
			tmpEntsFile, err := ioutil.TempFile("", "entitlements.plist")
			if err != nil {
				log.Error(err.Error())
				return
			}
			defer os.Remove(tmpEntsFile.Name()) // clean up
			if _, err := tmpEntsFile.Write(entitlementsData); err != nil {
				log.Error(err.Error())
				return
			}
			if err := tmpEntsFile.Close(); err != nil {
				log.Error(err.Error())
				return
			}

			// Read debugserver and write to tmp file
			roDbgSvr, err := os.Open("/tmp/dev_img/usr/bin/debugserver")
			if err != nil {
				log.Error(err.Error())
				return
			}
			defer roDbgSvr.Close()
			tmpDbgSrvFile, err := ioutil.TempFile("", "debugserver")
			if err != nil {
				log.Error(err.Error())
				return
			}
			defer os.Remove(tmpDbgSrvFile.Name()) // clean up
			if _, err := io.Copy(tmpDbgSrvFile, roDbgSvr); err != nil {
				log.Error(err.Error())
				return
			}
			if err := tmpDbgSrvFile.Close(); err != nil {
				log.Error(err.Error())
				return
			}

			utils.Indent(log.Info, 2)("Adding entitlements to /usr/bin/debugserver")
			if err := utils.CodeSignWithEntitlements(tmpDbgSrvFile.Name(), tmpEntsFile.Name(), "-"); err != nil {
				log.Error(err.Error())
				return
			}

			utils.Indent(log.Info, 2)("Copying /usr/bin/debugserver to device")
			dbgSvr, err := os.Open(tmpDbgSrvFile.Name())
			if err != nil {
				log.Error(err.Error())
				return
			}
			defer dbgSvr.Close()

			sessionSCP, err := client.NewSession()
			if err != nil {
				log.Fatalf("failed to create scp session: %s", err)
			}
			defer sessionSCP.Close()

			go func() error {
				w, _ := sessionSCP.StdinPipe()
				defer w.Close()

				count, err := io.Copy(w, dbgSvr)
				if err != nil {
					log.Error(err.Error())
					return err
				}
				if count == 0 {
					return fmt.Errorf("%d bytes copied to device", count)
				}

				return nil
			}()

			if err := sessionSCP.Start("cat > /usr/bin/debugserver"); err != nil {
				log.Error(err.Error())
				return
			}

			if err := sessionSCP.Wait(); err != nil {
				log.Error(err.Error())
				return
			}

			// chmod /usr/bin/debugserver
			sessionCHMOD, err := client.NewSession()
			if err != nil {
				log.Fatalf("failed to create chmod session: %s", err)
			}
			defer sessionCHMOD.Close()
			if err := sessionCHMOD.Start("chmod 0755 /usr/bin/debugserver"); err != nil {
				log.Error(err.Error())
				return
			}

			if err := sessionCHMOD.Wait(); err != nil {
				log.Error(err.Error())
				return
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
					log.Error(err.Error())
					return err
				}
				if count == 0 {
					return fmt.Errorf("%d bytes copied to device", count)
				}

				return nil
			}()

			if err := sessionLogSCP.Start("cat > /Library/Preferences/Logging/com.apple.system.logging.plist"); err != nil {
				log.Error(err.Error())
				return
			}

			if err := sessionLogSCP.Wait(); err != nil {
				log.Error(err.Error())
				return
			}

			/*
			 * killall logd
			 */
			utils.Indent(log.Info, 2)("Restarting logd")
			sessionKillAll, err := client.NewSession()
			if err != nil {
				log.Fatalf("failed to create killall session: %s", err)
			}
			defer sessionKillAll.Close()
			if err := sessionKillAll.Start("killall logd"); err != nil {
				log.Error(err.Error())
				return
			}
			if err := sessionKillAll.Wait(); err != nil {
				log.Error(err.Error())
				return
			}

		} else {
			log.Warn("debugserver already on device")
		}
	},
}
