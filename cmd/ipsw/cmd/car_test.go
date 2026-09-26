package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/pkg/car"
	"github.com/spf13/viper"
)

func configureCARTest(t *testing.T, values map[string]any) {
	t.Helper()
	defaults := map[string]any{
		"output": "", "json": false, "name": []string{}, "scale": "", "idiom": "",
		"appearance": "", "localization": "", "gamut": "", "metadata-only": false,
		"dry-run": false, "manifest": "", "render": false, "raw": false,
		"apply-orientation": false, "astc-decoder": "",
	}
	for key, value := range defaults {
		previous := viper.Get("car." + key)
		t.Cleanup(func() { viper.Set("car."+key, previous) })
		viper.Set("car."+key, value)
	}
	for key, value := range values {
		viper.Set("car."+key, value)
	}
}

func TestCARQueryAndDryRunOptions(t *testing.T) {
	configureCARTest(t, map[string]any{
		"name": []string{"Icon*", "Logo*"}, "scale": "2", "idiom": "0",
		"appearance": "1", "localization": "42", "gamut": "65535",
		"dry-run": true, "output": filepath.Join(t.TempDir(), "absent"), "render": true,
	})
	options, err := readCAROptions()
	if err != nil {
		t.Fatal(err)
	}
	query := options.config.Query
	if !reflect.DeepEqual(query.Names, []string{"Icon*", "Logo*"}) || query.Idiom == nil || *query.Idiom != 0 || *query.Scale != 2 || *query.Appearance != 1 || *query.Localization != 42 || *query.DisplayGamut != 65535 {
		t.Fatalf("query values lost: %+v", query)
	}
	if !options.config.MetadataOnly || options.config.Export || !options.config.Render {
		t.Fatalf("dry-run activated extraction: %+v", options.config)
	}
	if err := carCmd.RunE(carCmd, []string{filepath.Join(t.TempDir(), "missing.car")}); err == nil || !strings.Contains(err.Error(), "missing.car") {
		t.Fatalf("valid options failed before opening input: %v", err)
	}
	if _, err := os.Stat(options.config.Output); !os.IsNotExist(err) {
		t.Fatalf("dry-run created output folder: %v", err)
	}
}

func TestCARInvalidOptionsFailBeforeInput(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags map[string]any
		want  string
	}{
		{"overflow", map[string]any{"scale": "65536"}, "--scale"},
		{"negative", map[string]any{"idiom": "-1"}, "--idiom"},
		{"fractional", map[string]any{"gamut": "1.5"}, "--gamut"},
		{"pattern", map[string]any{"name": []string{"["}}, "--name"},
		{"raw render", map[string]any{"raw": true, "render": true}, "--raw"},
		{"raw orientation", map[string]any{"raw": true, "apply-orientation": true}, "--raw"},
		{"metadata export", map[string]any{"metadata-only": true, "output": "ignored"}, "--metadata-only"},
		{"orientation without export", map[string]any{"apply-orientation": true}, "--apply-orientation"},
		{"json dry-run", map[string]any{"json": true, "dry-run": true}, "--json"},
		{"json stdout manifest", map[string]any{"json": true, "manifest": "-"}, "--json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configureCARTest(t, tc.flags)
			if err := carCmd.RunE(carCmd, []string{"missing.car"}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %s validation, got %v", tc.want, err)
			}
		})
	}
}

func TestCARManifestDoesNotOverwriteAndStdoutIsJSON(t *testing.T) {
	a := &car.Asset{}
	var out bytes.Buffer
	if err := writeCARManifest(a, "planned", "-", &out); err != nil || !json.Valid(out.Bytes()) {
		t.Fatalf("stdout manifest is not JSON: %q, %v", out.String(), err)
	}
	filename := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(filename, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeCARManifest(a, "planned", filename, &out); err == nil {
		t.Fatal("existing manifest overwritten")
	}
	data, err := os.ReadFile(filename)
	if err != nil || string(data) != "keep" {
		t.Fatalf("existing manifest changed: %q, %v", data, err)
	}
}

func TestCARCommandIsVisibleAndDocumentsWorkflows(t *testing.T) {
	if carCmd.Hidden {
		t.Fatal("car command is hidden")
	}
	for _, flag := range []string{"metadata-only", "dry-run", "name", "scale", "idiom", "appearance", "localization", "gamut", "manifest", "render", "raw", "apply-orientation", "astc-decoder"} {
		if carCmd.Flags().Lookup(flag) == nil {
			t.Fatalf("missing public flag --%s", flag)
		}
	}
	for _, example := range []string{"--metadata-only", "--dry-run", "--name 'AppIcon*'", "--manifest exports.json", "--raw"} {
		if !strings.Contains(carCmd.Example, example) {
			t.Fatalf("help missing example %q", example)
		}
	}
}
