// +build cgo

/*
Copyright © 2019 blacktop

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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/dyld"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var deviceOsFlag string

func init() {
	dyldCmd.AddCommand(splitCmd)

	splitCmd.Flags().BoolP("iphone", "i", true, "Extract from iPhoneOS cache")
	splitCmd.Flags().BoolP("appletv", "a", false, "Extract from AppleTVOS cache")
	splitCmd.Flags().BoolP("watch", "w", false, "Extract from WatchOS cache")
}

func contains(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}

	_, ok := set[item]
	return ok
}

func checkRequiredFlags(flags *pflag.FlagSet) error {
	requiredError := false
	flagSetCount := 0

	flags.VisitAll(func(flag *pflag.Flag) {
		if contains([]string{"iphone", "appletv", "watch"}, flag.Name) {
			if strings.EqualFold(flag.Value.String(), "true") {
				flagSetCount++
				switch flag.Name {
				case "iphone":
					deviceOsFlag = "iPhoneOS"
				case "appletv":
					deviceOsFlag = "AppleTVOS"
				case "watch":
					deviceOsFlag = "WatchOS"
				}
			}

			if flagSetCount > 1 {
				requiredError = true
			}
		}
	})

	if requiredError {
		return errors.New("Flags are mutually exclusive: please only set one of -i|-a|-w")
	}

	return nil
}

// splitCmd represents the split command
var splitCmd = &cobra.Command{
	Use:   "split [path to dyld_shared_cache]",
	Short: "Extracts all the dyld_shared_cache libraries",
	Args:  cobra.MinimumNArgs(1),
	PreRunE: func(cmd *cobra.Command, args []string) error {
		return checkRequiredFlags(cmd.Flags())
	},
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		dscPath := filepath.Clean(args[0])

		if _, err := os.Stat(dscPath); os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", args[0])
		}

		if runtime.GOOS != "darwin" {
			log.Fatal("dyld_shared_cache splitting only works on macOS :(")
		}

		log.Info("Splitting dyld_shared_cache")
		return dyld.Split(dscPath, filepath.Dir(dscPath), deviceOsFlag)
	},
}
