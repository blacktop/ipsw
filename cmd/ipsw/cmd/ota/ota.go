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
package ota

import (
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var colorMode = color.New(color.FgHiBlue).SprintFunc()
var colorModTime = color.New(color.Faint).SprintFunc()
var colorSize = color.New(color.FgHiCyan).SprintFunc()
var colorName = color.New(color.Bold).SprintFunc()
var colorLink = color.New(color.FgHiMagenta).SprintFunc()

func init() {
	OtaCmd.PersistentFlags().String("key-val", "", "Base64 encoded symmetric encryption key")
	viper.BindPFlag("ota.key-val", OtaCmd.PersistentFlags().Lookup("key-val"))
}

// OtaCmd represents the ota command
var OtaCmd = &cobra.Command{
	Use:   "ota",
	Short: "Parse OTAs",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}
