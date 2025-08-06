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
package appstore

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	AppstoreCmd.PersistentFlags().StringP("p8", "p", "", "Path to App Store Connect API Key (.p8)")
	AppstoreCmd.PersistentFlags().StringP("iss", "i", "", "Issuer ID")
	AppstoreCmd.PersistentFlags().StringP("kid", "k", "", "Key ID")
	AppstoreCmd.PersistentFlags().StringP("jwt", "j", "", "JWT api key")
	viper.BindPFlag("appstore.p8", AppstoreCmd.PersistentFlags().Lookup("p8"))
	viper.BindPFlag("appstore.iss", AppstoreCmd.PersistentFlags().Lookup("iss"))
	viper.BindPFlag("appstore.kid", AppstoreCmd.PersistentFlags().Lookup("kid"))
	viper.BindPFlag("appstore.jwt", AppstoreCmd.PersistentFlags().Lookup("jwt"))
}

// AppstoreCmd represents the appstore command
var AppstoreCmd = &cobra.Command{
	Use:     "appstore",
	Aliases: []string{"as"},
	Short:   "Interact with the App Store Connect API",
	Args:    cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}
