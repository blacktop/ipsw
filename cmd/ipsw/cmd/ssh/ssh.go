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
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	SSHCmd.PersistentFlags().StringP("host", "t", "localhost", "ssh host")
	SSHCmd.PersistentFlags().StringP("port", "p", "2222", "ssh port")
	SSHCmd.PersistentFlags().StringP("user", "u", "root", "ssh user")
	SSHCmd.PersistentFlags().StringP("password", "s", "alpine", "ssh password")
	SSHCmd.PersistentFlags().StringP("key", "i", "$HOME/.ssh/id_rsa", "ssh key")
	SSHCmd.PersistentFlags().BoolP("insecure", "n", false, "ignore known_hosts")
	viper.BindPFlag("ssh.host", SSHCmd.Flags().Lookup("host"))
	viper.BindPFlag("ssh.port", SSHCmd.Flags().Lookup("port"))
	viper.BindPFlag("ssh.user", SSHCmd.Flags().Lookup("user"))
	viper.BindPFlag("ssh.password", SSHCmd.Flags().Lookup("password"))
	viper.BindPFlag("ssh.key", SSHCmd.Flags().Lookup("key"))
	viper.BindPFlag("ssh.insecure", SSHCmd.Flags().Lookup("insecure"))
}

// SSHCmd represents the ssh command
var SSHCmd = &cobra.Command{
	Use:   "ssh",
	Short: "SSH into a jailbroken device",
	Args:  cobra.NoArgs,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		viper.BindPFlag("color", cmd.Flags().Lookup("color"))
		viper.BindPFlag("no-color", cmd.Flags().Lookup("no-color"))
		viper.BindPFlag("verbose", cmd.Flags().Lookup("verbose"))
	},
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}
