package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/apex/log"
	"github.com/apex/log/handlers/memory"
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

// A credential that happens to look like a path is neither rewritten nor
// logged, while an ordinary path beside it is still expanded and reported.
func TestExpandSettingsLeavesCredentialsAlone(t *testing.T) {
	// The list is repeated here on purpose: removing an exemption from the
	// map, or adding one, must be a deliberate change in both places.
	credentials := []string{
		"appstore.jwt",
		"database.password",
		"dmg.password",
		"download.appledb.api-token",
		"download.dev.password",
		"download.dev.vault-password",
		"download.git.api",
		"download.ipa.password",
		"download.ipa.vault-password",
		"dyld.disass.dec-api-key",
		"dyld.webkit.api",
		"ent.pg-password",
		"macho.disass.dec-api-key",
		"macho.sign.pw",
		"ssh.password",
		"symbolicate.api-token",
		"update.api",
		"watch.api",
		"watch.discord-token",
		"watch.mastodon-access-token",
		"watch.mastodon-client-secret",
	}
	if len(sensitiveConfigKeys) != len(credentials) {
		t.Fatalf("sensitiveConfigKeys has %d entries, this test expects %d", len(sensitiveConfigKeys), len(credentials))
	}
	for _, key := range credentials {
		if !sensitiveConfigKeys[key] {
			t.Errorf("%s is not exempt from path expansion", key)
		}
	}
	for _, key := range credentials {
		t.Run(key, func(t *testing.T) {
			const secret = "~/looks-like-a-path-Qm4r8Tz1Wd"
			handler := memory.New()
			logger, ok := log.Log.(*log.Logger)
			if !ok {
				t.Fatal("apex logger has an unexpected implementation")
			}
			previous := logger.Handler
			log.SetHandler(handler)
			t.Cleanup(func() { log.SetHandler(previous) })

			// Build the nested map a YAML file with this dotted key produces.
			parts := strings.Split(key, ".")
			settings := map[string]any{"control-path": "~/control-Hn3x"}
			level := settings
			for _, part := range parts[:len(parts)-1] {
				next := map[string]any{}
				level[part] = next
				level = next
			}
			level[parts[len(parts)-1]] = secret

			expandSettings(settings, "", false)

			if level[parts[len(parts)-1]] != secret {
				t.Errorf("credential was rewritten: %q", level[parts[len(parts)-1]])
			}
			if settings["control-path"] == "~/control-Hn3x" {
				t.Error("the ordinary path was not expanded")
			}
			warned := false
			for _, entry := range handler.Entries {
				if strings.Contains(entry.Message, "Qm4r8Tz1Wd") {
					t.Errorf("credential value was logged: %q", entry.Message)
				}
				if strings.Contains(entry.Message, "control-path") {
					warned = true
				}
			}
			if !warned {
				t.Error("the ordinary path produced no warning; the leak check would be vacuous")
			}
		})
	}
}
