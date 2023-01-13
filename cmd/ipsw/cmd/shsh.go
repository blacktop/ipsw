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
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/shsh"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const defaultKeyPath = "$HOME/.ssh/id_rsa"

func keyString(k ssh.PublicKey) string {
	return k.Type() + " " + base64.StdEncoding.EncodeToString(k.Marshal())
}

func addHostKey(known_hosts string, remote net.Addr, pubKey ssh.PublicKey) error {
	f, err := os.OpenFile(known_hosts, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open known_hosts: %w", err)
	}
	defer f.Close()

	_, err = f.WriteString(knownhosts.Line([]string{knownhosts.Normalize(remote.String())}, pubKey))
	return err
}

func init() {
	rootCmd.AddCommand(shshCmd)
	shshCmd.Flags().StringP("host", "t", "localhost", "ssh host")
	shshCmd.Flags().StringP("port", "p", "2222", "ssh port")
	shshCmd.Flags().StringP("key", "i", defaultKeyPath, "ssh key")
	shshCmd.Flags().BoolP("insecure", "n", false, "ignore known_hosts key checking")
	viper.BindPFlag("shsh.host", shshCmd.Flags().Lookup("host"))
	viper.BindPFlag("shsh.port", shshCmd.Flags().Lookup("port"))
	viper.BindPFlag("shsh.key", shshCmd.Flags().Lookup("key"))
	viper.BindPFlag("shsh.insecure", shshCmd.Flags().Lookup("insecure"))
}

// shshCmd represents the shsh command
var shshCmd = &cobra.Command{
	Use:           "shsh",
	Short:         "Get shsh blobs from device",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		sshHost := viper.GetString("shsh.host")
		sshPort := viper.GetString("shsh.port")
		sshKey := viper.GetString("shsh.key")

		home, err := os.UserHomeDir()
		if err != nil {
			panic(fmt.Sprintf("failed to get user home directory: %v", err))
		}

		knownhostsPath := filepath.Join(home, ".ssh", "known_hosts")

		var signer ssh.Signer
		if len(sshKey) > 0 {
			if sshKey == defaultKeyPath {
				sshKey = filepath.Join(home, ".ssh", "id_rsa")
			}
			key, err := os.ReadFile(sshKey)
			if err != nil {
				return fmt.Errorf("failed to read private key: %w", err)
			}
			signer, err = ssh.ParsePrivateKey(key)
			if err != nil {
				return fmt.Errorf("failed to parse private key: %w", err)
			}
		}

		var sshConfig *ssh.ClientConfig
		if viper.GetBool("shsh.insecure") {
			sshConfig = &ssh.ClientConfig{
				User: "root",
				Auth: []ssh.AuthMethod{
					ssh.PublicKeys(signer),
					ssh.Password("alpine"),
				},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			}
		} else {
			var hostKeyCallback ssh.HostKeyCallback
			if _, err := os.Stat(knownhostsPath); err == nil {
				hostKeyCallback, err = knownhosts.New(knownhostsPath)
				if err != nil {
					return err
				}
			} else if errors.Is(err, os.ErrNotExist) {
				f, err := os.OpenFile(knownhostsPath, os.O_CREATE, 0600)
				if err != nil {
					return err
				}
				f.Close()
				hostKeyCallback, err = knownhosts.New(knownhostsPath)
				if err != nil {
					return err
				}
			} else {
				return fmt.Errorf("failed to open known_hosts: %w", err)
			}

			sshConfig = &ssh.ClientConfig{
				User: "root",
				Auth: []ssh.AuthMethod{
					ssh.PublicKeys(signer),
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

		if err = shsh.ParseRAW(r); err != nil {
			return err
		}

		if err := session.Wait(); err != nil {
			return err
		}

		return nil
	},
}
