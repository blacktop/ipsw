/*
Copyright © 2023 blacktop

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

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/car"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(carCmd)
	carCmd.Flags().BoolP("export", "x", false, "Export all renditions")
	viper.BindPFlag("car.export", carCmd.Flags().Lookup("export"))
}

// carCmd represents the car command
var carCmd = &cobra.Command{
	Use:           "car",
	Short:         "Parse Asset.car files",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	Hidden:        true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		// if err := filepath.Walk("/tmp/098-38745-038.dmg.mount", func(path string, info fs.FileInfo, err error) error {
		// 	if err != nil {
		// 		return fmt.Errorf("prevent panic by handling failure accessing a path %q: %v", path, err)
		// 	}
		// 	if info.IsDir() {
		// 		return nil
		// 		// return filepath.SkipDir
		// 	}
		// 	if filepath.Ext(path) == ".car" {
		// 		if _, err := car.Parse(path, &car.Config{Verbose: Verbose}); err != nil {
		// 			log.Errorf("failed to parse %s: %v", path, err)
		// 		}
		// 	}
		// 	return nil
		// }); err != nil {
		// 	return err
		// }

		asset, err := car.Parse(args[0], &car.Config{
			Export:  viper.GetBool("car.export"),
			Verbose: Verbose,
		})
		if err != nil {
			return err
		}

		fmt.Println(asset)

		return nil
	},
}
