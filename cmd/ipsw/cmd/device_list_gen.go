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
	Use:   "gen",
	Short: "Generate iOS devices database",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {

		devices, err := xcode.ReadDeviceTraitsDB()
		if err != nil {
			return err
		}

		err = xcode.WriteToJSON(devices)
		if err != nil {
			return err
		}

		return nil
	},
}
