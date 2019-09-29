// +build darwin,cgo

package cmd

import (
	"github.com/blacktop/ipsw/pkg/xcode"
	"github.com/spf13/cobra"
)

func init() {
	listCmd.AddCommand(genCmd)
}

// genCmd represents the gen command
var genCmd = &cobra.Command{
	Use:   "gen [output PATH]",
	Short: "Generate iOS devices database",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		devices, err := xcode.ReadDeviceTraitsDB()
		if err != nil {
			return err
		}

		err = xcode.WriteToJSON(devices, args[0])
		if err != nil {
			return err
		}

		return nil
	},
}
