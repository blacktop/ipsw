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
package idev

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/usb/misagent"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	ProvCmd.AddCommand(provDumpCmd)
	provDumpCmd.Flags().StringP("output", "o", "", "Folder to save profiles(s)")
	provDumpCmd.MarkFlagDirname("output")
}

// provDumpCmd represents the dump command
var provDumpCmd = &cobra.Command{
	Use:           "dump",
	Short:         "Dump installed provision profiles",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		udid, _ := cmd.Flags().GetString("udid")
		output, _ := cmd.Flags().GetString("output")

		if len(udid) == 0 {
			dev, err := utils.PickDevice()
			if err != nil {
				return fmt.Errorf("failed to pick USB connected devices: %w", err)
			}
			udid = dev.UniqueDeviceID
		}

		ms, err := misagent.NewClient(udid)
		if err != nil {
			return fmt.Errorf("failed to create misagent client: %w", err)
		}

		profs, err := ms.List()
		if err != nil {
			return fmt.Errorf("failed to list provision profiles: %w", err)
		}

		log.Info("Dumping provision profiles...")
		for _, prof := range profs {
			if err := os.WriteFile(filepath.Join(output, prof.UUID+".mobileprovision"), prof.Bytes(), 0644); err != nil {
				return fmt.Errorf("failed to write provision profile %s to disk: %w", filepath.Join(output, prof.UUID+".mobileprovision"), err)
			}
		}

		return nil
	},
}
