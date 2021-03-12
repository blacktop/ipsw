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
	"github.com/rakyll/statik/fs"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	// importing statik data
	_ "github.com/blacktop/ipsw/internal/statik"
)

func init() {
	rootCmd.AddCommand(debugserverCmd)
	debugserverCmd.Flags().StringP("port", "p", "2222", "ssh port")
	debugserverCmd.Flags().BoolP("force", "f", false, "overwrite file on device")
}

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

		sshPort, _ := cmd.Flags().GetString("port")
		force, _ := cmd.Flags().GetBool("force")

		home, err := homedir.Dir()
		if err != nil {
			log.Fatal(err.Error())
		}

		hostKeyCallback, err := knownhosts.New(filepath.Join(home, ".ssh/known_hosts"))
		if err != nil {
			log.Fatal(err.Error())
		}

		sshConfig := &ssh.ClientConfig{
			User: "root",
			Auth: []ssh.AuthMethod{
				ssh.Password("alpine"),
			},
			HostKeyCallback: hostKeyCallback,
		}

		utils.Indent(log.Info, 1)(fmt.Sprintf("Connecting to root@localhost:%s", sshPort))

		client, err := ssh.Dial("tcp", "localhost:"+sshPort, sshConfig)
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
				log.Fatal(err.Error())
			}
			betaImages, err := filepath.Glob("/Applications/Xcode-beta.app/Contents/Developer/Platforms/iPhoneOS.platform/DeviceSupport/*/DeveloperDiskImage.dmg")
			if err != nil {
				log.Fatal(err.Error())
			}
			images = append(images, betaImages...)

			choice := 0
			prompt := &survey.Select{
				Message: fmt.Sprintf("Select the DeveloperDiskImage you want to extract the debugserver from:"),
				Options: images,
			}
			survey.AskOne(prompt, &choice)
			// dmg := "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/DeviceSupport/14.4/DeveloperDiskImage.dmg"
			utils.Indent(log.Info, 2)("Mounting DeveloperDiskImage")
			// if err := utils.Mount(dmg, "/tmp/dev_img"); err != nil {
			if err := utils.Mount(images[choice], "/tmp/dev_img"); err != nil {
				utils.Indent(log.Fatal, 2)(fmt.Sprintf("failed to mount %s: %v", images[choice], err))
				// utils.Indent(log.Fatal, 2)(fmt.Sprintf("failed to mount %s: %v", dmg, err))
			}
			defer func() {
				utils.Indent(log.Info, 2)("Unmounting DeveloperDiskImage")
				if err := utils.Unmount("/tmp/dev_img"); err != nil {
					utils.Indent(log.Fatal, 2)(fmt.Sprintf("failed to unmount /tmp/dev_img: %v", err))
				}
			}()

			statikFS, err := fs.New()
			if err != nil {
				log.Fatal(err.Error())
			}
			plist, err := statikFS.Open("/debugserver.plist")
			if err != nil {
				log.Fatal(err.Error())
			}

			data, err := ioutil.ReadAll(plist)
			if err != nil {
				log.Fatal(err.Error())
			}

			tmpEntsFile, err := ioutil.TempFile("", "entitlements.plist")
			if err != nil {
				log.Fatal(err.Error())
			}
			defer os.Remove(tmpEntsFile.Name()) // clean up

			f, err := os.Open("/tmp/dev_img/usr/bin/debugserver")
			if err != nil {
				log.Fatal(err.Error())
			}
			defer f.Close()

			tmpDbgSrvFile, err := ioutil.TempFile("", "debugserver")
			if err != nil {
				log.Fatal(err.Error())
			}
			defer os.Remove(tmpDbgSrvFile.Name()) // clean up

			if _, err := io.Copy(tmpDbgSrvFile, f); err != nil {
				log.Fatal(err.Error())
			}
			if err := tmpDbgSrvFile.Close(); err != nil {
				log.Fatal(err.Error())
			}

			if _, err := tmpEntsFile.Write(data); err != nil {
				log.Fatal(err.Error())
			}
			if err := tmpEntsFile.Close(); err != nil {
				log.Fatal(err.Error())
			}

			utils.Indent(log.Info, 2)("Adding entitlements to /usr/bin/debugserver")
			if err := utils.CodeSignWithEntitlements(tmpDbgSrvFile.Name(), tmpEntsFile.Name(), "-"); err != nil {
				log.Fatal(err.Error())
			}

			utils.Indent(log.Info, 2)("Copying /usr/bin/debugserver to device")
			sessionSCP, err := client.NewSession()
			if err != nil {
				log.Fatalf("failed to create scp session: %s", err)
			}
			defer sessionSCP.Close()

			go func() error {
				w, _ := sessionSCP.StdinPipe()
				defer w.Close()
				count, err := io.Copy(w, f)
				if err != nil {
					log.Fatal(err.Error())
				}
				if count == 0 {
					return fmt.Errorf("%d bytes copied to device", count)
				}
				return nil
			}()

			if err := sessionSCP.Start("cat > /usr/bin/debugserver"); err != nil {
				log.Fatal(err.Error())
			}

			if err := sessionSCP.Wait(); err != nil {
				log.Fatal(err.Error())
			}

		} else {
			log.Warn("debugserver already on device")
		}
	},
}
