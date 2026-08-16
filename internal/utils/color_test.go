package utils

import (
	"testing"

	"github.com/fatih/color"
	"github.com/spf13/viper"
)

func TestColorPolicy(t *testing.T) {
	previousNoColor := color.NoColor
	previousColorSetting := viper.Get("color")
	previousNoColorSetting := viper.Get("no-color")
	t.Cleanup(func() {
		color.NoColor = previousNoColor
		viper.Set("color", previousColorSetting)
		viper.Set("no-color", previousNoColorSetting)
	})

	tests := []struct {
		name            string
		colorSetting    bool
		noColorSetting  bool
		autoDetectedOff bool
		wantAllowed     bool
		wantEnabled     bool
	}{
		{name: "enabled terminal", colorSetting: true, wantAllowed: true, wantEnabled: true},
		{name: "not requested", wantAllowed: true},
		{name: "disabled by flag", colorSetting: true, noColorSetting: true},
		{name: "redirected stdout", colorSetting: true, autoDetectedOff: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			viper.Set("color", test.colorSetting)
			viper.Set("no-color", test.noColorSetting)
			color.NoColor = test.autoDetectedOff

			if got := ColorAllowed(); got != test.wantAllowed {
				t.Errorf("ColorAllowed() = %t, want %t", got, test.wantAllowed)
			}
			if got := ColorEnabled(); got != test.wantEnabled {
				t.Errorf("ColorEnabled() = %t, want %t", got, test.wantEnabled)
			}
		})
	}
}
