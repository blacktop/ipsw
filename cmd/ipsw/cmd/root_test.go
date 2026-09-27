package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fatih/color"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func TestExpandConfigPathsPreservesFlagAndEnvironmentPrecedence(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte("output: ./config-output\ndyld:\n  objc:\n    class:\n      image: config-image\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	v := viper.New()
	v.SetConfigFile(configPath)
	v.Set("config-quiet", true)
	if err := v.ReadInConfig(); err != nil {
		t.Fatal(err)
	}
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	flags.Bool("class", false, "")
	flags.String("image", "", "")
	if err := v.BindPFlag("dyld.objc.dump-class", flags.Lookup("class")); err != nil {
		t.Fatal(err)
	}
	if err := v.BindPFlag("dyld.objc.class.image", flags.Lookup("image")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("IPSW_TEST_IMAGE", "env-image")
	if err := v.BindEnv("dyld.objc.class.image", "IPSW_TEST_IMAGE"); err != nil {
		t.Fatal(err)
	}
	if err := expandConfigPaths(v); err != nil {
		t.Fatal(err)
	}
	want, err := filepath.Abs("config-output")
	if err != nil {
		t.Fatal(err)
	}
	if got := v.GetString("output"); got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
	if got := v.GetString("dyld.objc.class.image"); got != "env-image" {
		t.Fatalf("image = %q, want environment value", got)
	}
	if err := flags.Set("image", "flag-image"); err != nil {
		t.Fatal(err)
	}
	if got := v.GetString("dyld.objc.class.image"); got != "flag-image" {
		t.Fatalf("image = %q, want changed flag value", got)
	}
}

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

func TestExpandExtensionlessYAMLConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte("output: ./synthetic-output\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	v.Set("config-quiet", true)
	if err := v.ReadInConfig(); err != nil {
		t.Fatal(err)
	}
	if err := expandConfigPaths(v); err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(v.GetString("output")) {
		t.Fatalf("path was not expanded: %q", v.GetString("output"))
	}
}
