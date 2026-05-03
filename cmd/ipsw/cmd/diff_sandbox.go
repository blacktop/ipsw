//go:build sandbox

package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func registerDiffSandboxFlags(cmd *cobra.Command) {
	cmd.Flags().Bool("sandbox", false, "Diff compiled sandbox profiles")
	viper.BindPFlag("diff.sandbox", cmd.Flags().Lookup("sandbox"))
}

func diffSandboxEnabled() bool {
	return viper.GetBool("diff.sandbox")
}

func diffSandboxPreflight() error {
	return nil
}
