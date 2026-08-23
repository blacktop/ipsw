package cmd

import (
	"testing"

	"github.com/fatih/color"
	"github.com/spf13/viper"
)

func TestRootPreservesAutoDetectedNoColor(t *testing.T) {
	previousNoColor := color.NoColor
	previousSetting := viper.Get("no-color")
	t.Cleanup(func() {
		color.NoColor = previousNoColor
		viper.Set("no-color", previousSetting)
	})

	color.NoColor = true
	viper.Set("no-color", false)

	if err := rootCmd.PersistentPreRunE(rootCmd, nil); err != nil {
		t.Fatal(err)
	}

	if !color.NoColor {
		t.Fatal("root command enabled color after stdout was detected as non-terminal")
	}
}
