//go:build darwin && cgo && objc

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
package cmd

import (
	"fmt"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/objc"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(objcCmd)
}

// objcCmd represents the obj command
var objcCmd = &cobra.Command{
	Use:           "objc <CLASS>",
	Short:         "Dump Objective-C info in running `ipsw` process",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	Hidden:        true,
	Run: func(cmd *cobra.Command, args []string) {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		// BlastDoor, err := objc.LoadImage("/System/Library/PrivateFrameworks/BlastDoor.framework/BlastDoor")
		// if err != nil {
		// 	log.Error(err.Error())
		// 	return
		// }
		// defer BlastDoor.Close()

		log.Infof("Dumping Objective-C info in running `ipsw` process for class: %s", args[0])

		for _, img := range objc.ImageNames() {
			fmt.Println(img)
			for _, cls := range objc.ClassNamesForImage(img) {
				fmt.Printf("\t%s\n", cls)
			}
		}

		NSObject := objc.GetClass(args[0])

		fmt.Println(NSObject.GetImageName())

		fmt.Println("@methods")
		for _, m := range NSObject.Methods() {
			fmt.Printf("%s %s", m.ReturnType(), m.Name())
			var args []string
			for i := 2; i < m.ArgumentCount(); i++ {
				args = append(args, m.ArgumentType(i))
			}
			if len(args) > 0 {
				fmt.Printf("(%s)\n", strings.Join(args, ", "))
			} else {
				fmt.Printf("\n")
			}
		}

		fmt.Println("@properties")
		for _, p := range NSObject.Properties() {
			fmt.Printf("%s %s\n", p.Name(), p.Attributes())
		}

		fmt.Println("@ivars")
		for _, i := range NSObject.Ivars() {
			fmt.Printf("%s %s\n", i.Name(), i.TypeEncoding())
		}
	},
}
