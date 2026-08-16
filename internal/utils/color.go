package utils

import (
	"github.com/fatih/color"
	"github.com/spf13/viper"
)

// ColorAllowed reports whether color output is safe for stdout.
func ColorAllowed() bool {
	return !viper.GetBool("no-color") && !color.NoColor
}

// ColorEnabled reports whether color was requested and is safe for stdout.
func ColorEnabled() bool {
	return viper.GetBool("color") && ColorAllowed()
}
