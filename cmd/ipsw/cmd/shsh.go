/*
Copyright © 2018-2022 blacktop

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
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/shsh"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func init() {
	rootCmd.AddCommand(shshCmd)
}

// shshCmd represents the shsh command
var shshCmd = &cobra.Command{
	Use:   "shsh",
	Short: "Get shsh blobs from device",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			return err
		}

		hostKeyCallback, err := knownhosts.New(filepath.Join(home, ".ssh/known_hosts"))
		if err != nil {
			return err
		}

		sshConfig := &ssh.ClientConfig{
			User: "root",
			Auth: []ssh.AuthMethod{
				ssh.Password("alpine"),
			},
			HostKeyCallback: hostKeyCallback,
		}

		utils.Indent(log.Info, 1)("Connecting to root@localhost:2222")

		client, err := ssh.Dial("tcp", "localhost:2222", sshConfig)
		if err != nil {
			return fmt.Errorf("failed to dial: %s", err)
		}

		session, err := client.NewSession()
		if err != nil {
			return fmt.Errorf("failed to create session: %s", err)
		}
		defer session.Close()

		r, err := session.StdoutPipe()
		if err != nil {
			return err
		}

		if err := session.Start("cat /dev/rdisk1 | dd bs=256 count=$((0x4000))"); err != nil {
			return err
		}

		err = shsh.ParseRAW(r)
		if err != nil {
			return err
		}

		if err := session.Wait(); err != nil {
			return err
		}

		return nil
	},
}
