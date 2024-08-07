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
package ssh

import (
	"bytes"
	"fmt"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/ssh"
	"github.com/blacktop/ipsw/pkg/shsh"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	SSHCmd.AddCommand(sshShshBlobCmd)
}

// sshShshBlobCmd represents the shsh command
var sshShshBlobCmd = &cobra.Command{
	Use:           "shsh",
	Aliases:       []string{"sh"},
	Short:         "Get shsh blobs from device",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// parent flags
		viper.BindPFlag("ssh.host", cmd.Flags().Lookup("host"))
		viper.BindPFlag("ssh.port", cmd.Flags().Lookup("port"))
		viper.BindPFlag("ssh.user", cmd.Flags().Lookup("user"))
		viper.BindPFlag("ssh.password", cmd.Flags().Lookup("password"))
		viper.BindPFlag("ssh.key", cmd.Flags().Lookup("key"))
		viper.BindPFlag("ssh.insecure", cmd.Flags().Lookup("insecure"))

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

		out, err := cli.GetShshBlobs()
		if err != nil {
			return fmt.Errorf("failed to get shsh blobs: %w", err)
		}

		return shsh.ParseRAW(bytes.NewReader(out))
	},
}
