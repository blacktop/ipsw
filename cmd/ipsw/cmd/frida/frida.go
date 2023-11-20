//go:build darwin && frida

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
package frida

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const fridaVersion = "16.1.7"

func init() {
	FridaCmd.PersistentFlags().StringP("udid", "u", "", "Device UniqueDeviceID to connect to")
}

// FridaCmd represents the frida commands
var FridaCmd = &cobra.Command{
	Use:     "frida",
	Aliases: []string{"f"},
	Short:   "Run Frida commands",
	Args:    cobra.NoArgs,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		viper.BindPFlag("color", cmd.Flags().Lookup("color"))
		viper.BindPFlag("verbose", cmd.Flags().Lookup("verbose"))
		viper.BindPFlag("frida.udid", cmd.Flags().Lookup("udid"))
		viper.BindPFlag("diff-tool", cmd.Flags().Lookup("diff-tool"))
	},
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}
