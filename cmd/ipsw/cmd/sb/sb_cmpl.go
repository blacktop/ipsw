//go:build sandbox && cgo

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
package sb

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/sandbox"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	SbCmd.AddCommand(cmplCmd)
	cmplCmd.Flags().StringP("output", "o", "", "Folder to save profile.bin to")
	cmplCmd.MarkFlagDirname("output")
}

// cmplCmd represents the cmpl command
var cmplCmd = &cobra.Command{
	Use:           "cmpl",
	Short:         "Compile a sandbox profile",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	Hidden:        true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		output, _ := cmd.Flags().GetString("output")

		sbProfile := filepath.Clean(args[0])

		f, err := os.Open(sbProfile)
		if err != nil {
			return err
		}
		defer f.Close()

		profile, err := sandbox.Compile(f)
		if err != nil {
			return fmt.Errorf("failed to compile profile %s: %w", sbProfile, err)
		}

		if len(output) > 0 {
			if err := os.MkdirAll(output, 0755); err != nil {
				return err
			}
			output = filepath.Join(output, "profile.bin")
		} else {
			output = "profile.bin"
		}

		log.Infof("Compiling profile to %s", output)
		return os.WriteFile(output, profile, 0644)
	},
}
