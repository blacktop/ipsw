package cmd

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

const symbolsComponentTestManifest = `<plist version="1.0"><dict><key>ProductVersion</key><string>99.0</string><key>ProductBuildVersion</key><string>99A1</string><key>SupportedProductTypes</key><array><string>Mac99,1</string></array><key>BuildIdentities</key><array><dict><key>Info</key><dict><key>DeviceClass</key><string>boarda</string></dict><key>Manifest</key><dict><key>KernelCache</key><dict><key>Info</key><dict><key>Path</key><string>kernelcache.release.test</string></dict></dict></dict></dict></array></dict></plist>`

func symbolsComponentTestSource(t *testing.T) string {
	t.Helper()
	var data bytes.Buffer
	z := zip.NewWriter(&data)
	for _, entry := range []struct{ name, data string }{
		{"BuildManifest.plist", symbolsComponentTestManifest},
		{"kernelcache.release.test", "deliberately invalid IMG4"},
	} {
		w, err := z.Create(entry.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(entry.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "synthetic.ipsw")
	if err := os.WriteFile(path, data.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func setSymbolsTestFlags(t *testing.T, values map[string]string) {
	t.Helper()
	for name, value := range values {
		flag := symbolsCmd.Flags().Lookup(name)
		// Other command tests reset Viper's package-global bindings. Rebind
		// these real flags so a full package run exercises the same CLI path.
		if err := viper.BindPFlag("symbols."+name, flag); err != nil {
			t.Fatal(err)
		}
		oldValue, oldChanged := flag.Value.String(), flag.Changed
		t.Cleanup(func() {
			if err := flag.Value.Set(oldValue); err != nil {
				t.Error(err)
			}
			flag.Changed = oldChanged
		})
		if err := symbolsCmd.Flags().Set(name, value); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSymbolsComponentInterfaceIsHidden(t *testing.T) {
	usage := symbolsCmd.Flags().FlagUsages()
	for _, name := range []string{"component-name", "component-path", "component-variant"} {
		flag := symbolsCmd.Flags().Lookup(name)
		if flag == nil || !flag.Hidden {
			t.Fatalf("private integration flag %q is missing or visible", name)
		}
		if strings.Contains(usage, name) || strings.Contains(symbolsCmd.Long, "--"+name) {
			t.Fatalf("private integration flag %q appears in help", name)
		}
	}
	if strings.Contains(symbolsCmd.Long, "symbols_component_complete") {
		t.Fatal("private integration protocol appears in command help")
	}
}

func TestSymbolsComponentValidatesBeforeOutput(t *testing.T) {
	source := symbolsComponentTestSource(t)
	for _, tc := range []struct{ name, path, variant, kernel, dyld, json string }{
		{"missing member", "kernelcache.release.missing", "release", "true", "false", "true"},
		{"variant mismatch", "kernelcache.release.test", "research", "true", "false", "true"},
		{"unsupported family", "kernelcache.release.test", "release", "false", "true", "true"},
		{"missing family", "kernelcache.release.test", "release", "false", "false", "true"},
		{"non JSON", "kernelcache.release.test", "release", "true", "false", "false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "existing.jsonl")
			if err := os.WriteFile(out, []byte("retain me"), 0600); err != nil {
				t.Fatal(err)
			}
			setSymbolsTestFlags(t, map[string]string{
				"component-name": "KernelCache", "component-path": tc.path, "component-variant": tc.variant,
				"kernel": tc.kernel, "dyld": tc.dyld, "filesystem": "false", "json": tc.json, "output": out,
			})
			if err := symbolsCmd.RunE(symbolsCmd, []string{source}); err == nil {
				t.Fatal("invalid selection succeeded")
			}
			if raw, err := os.ReadFile(out); err != nil || string(raw) != "retain me" {
				t.Fatalf("output changed before selection validation: %q %v", raw, err)
			}
		})
	}
	setSymbolsTestFlags(t, map[string]string{"component-name": "KernelCache", "component-path": "kernelcache.release.test",
		"component-variant": "release", "kernel": "true", "dyld": "false", "filesystem": "false", "json": "true", "output": source})
	before, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := symbolsCmd.RunE(symbolsCmd, []string{source}); err == nil || !strings.Contains(err.Error(), "must not overwrite source") {
		t.Fatalf("source output alias accepted: %v", err)
	}
	if after, err := os.ReadFile(source); err != nil || !bytes.Equal(before, after) {
		t.Fatal("source was overwritten")
	}
}

func TestSymbolsComponentDiskOptionsBeforeOutput(t *testing.T) {
	for _, tc := range []struct{ name, path, variant, kernel, dyld, filesystem string }{
		{"OS", "os.dmg", "", "true", "false", "false"},
		{"Cryptex1,SystemOS", "system.dmg", "research", "false", "true", "true"},
		{"Cryptex1,AppOS", "app.dmg", "", "false", "true", "false"},
		{"Ap,ExclaveOS", "exclave.dmg", "", "false", "true", "false"},
		{"Cryptex1,RosettaOS", "rosetta.dmg", "", "false", "true", "false"},
		{"BaseSystem", "base.dmg", "", "false", "false", "true"},
		{"KernelCache", "kernelcache.release.test", "release", "true", "true", "false"},
		{"KernelCache", "kernelcache.release.test", "release", "true", "false", "true"},
	} {
		t.Run(tc.name+"-"+tc.dyld+"-"+tc.filesystem, func(t *testing.T) {
			dir := t.TempDir()
			out := filepath.Join(dir, "existing.jsonl")
			if err := os.WriteFile(out, []byte("retain me"), 0600); err != nil {
				t.Fatal(err)
			}
			setSymbolsTestFlags(t, map[string]string{
				"component-name": tc.name, "component-path": tc.path, "component-variant": tc.variant,
				"kernel": tc.kernel, "dyld": tc.dyld, "filesystem": tc.filesystem, "json": "true", "output": out,
			})
			err := symbolsCmd.RunE(symbolsCmd, []string{filepath.Join(dir, "missing.ipsw")})
			if err == nil || strings.Contains(err.Error(), "does not exist") {
				t.Fatalf("unavailable operation reached source I/O: %v", err)
			}
			if raw, err := os.ReadFile(out); err != nil || string(raw) != "retain me" {
				t.Fatalf("unavailable operation changed output: %q %v", raw, err)
			}
		})
	}
	for _, tc := range []struct{ name, path, dyld, filesystem string }{
		{"OS", "os.dmg", "false", "true"},
		{"Cryptex1,SystemOS", "system.dmg", "true", "true"},
		{"Cryptex1,AppOS", "app.dmg", "false", "true"},
		{"Ap,ExclaveOS", "exclave.dmg", "false", "true"},
	} {
		t.Run("accepted "+tc.name, func(t *testing.T) {
			dir := t.TempDir()
			out := filepath.Join(dir, "absent.jsonl")
			setSymbolsTestFlags(t, map[string]string{
				"component-name": tc.name, "component-path": tc.path, "component-variant": "",
				"kernel": "false", "dyld": tc.dyld, "filesystem": tc.filesystem, "json": "true", "output": out,
			})
			if err := symbolsCmd.RunE(symbolsCmd, []string{filepath.Join(dir, "missing.ipsw")}); err == nil || !strings.Contains(err.Error(), "does not exist") {
				t.Fatalf("supported disk options did not reach source validation: %v", err)
			}
			if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("output created before source validation: %v", err)
			}
		})
	}
}

func TestSymbolsComponentSubprocessExit(t *testing.T) {
	if idx := slices.Index(os.Args, "symbols-component-test-child"); idx >= 0 {
		rootCmd.SetArgs([]string{"symbols", "--component-name", "KernelCache", "--component-path", "kernelcache.release.test",
			"--component-variant", "release", "--kernel", "--output", os.Args[idx+2], os.Args[idx+1]})
		Execute() // Exercise the same error-to-exit path as cmd/ipsw/main.go.
		t.Fatal("malformed component scan returned with exit zero")
	}
	t.Setenv("IPSW_NO_UPDATE_CHECK", "1")
	source, output := symbolsComponentTestSource(t), filepath.Join(t.TempDir(), "partial.jsonl")
	cmd := exec.Command(os.Args[0], "-test.run=^TestSymbolsComponentSubprocessExit$", "--", "symbols-component-test-child", source, output)
	combined, err := cmd.CombinedOutput()
	var exited *exec.ExitError
	if !errors.As(err, &exited) || exited.ExitCode() != 1 {
		t.Fatalf("scan exit=%v output=%s", err, combined)
	}
	raw, err := os.ReadFile(output)
	if err != nil || !bytes.Contains(raw, []byte(`symbols_component_start`)) || bytes.Contains(raw, []byte(`symbols_component_complete`)) {
		t.Fatalf("failed scan terminal: %s, %v; process output=%s", raw, err, combined)
	}
}

func TestSymbolsRunsWithoutJSONFlag(t *testing.T) {
	t.Setenv("IPSW_NO_UPDATE_CHECK", "1")
	missingIPSW := filepath.Join(t.TempDir(), "missing.ipsw")

	err := symbolsCmd.RunE(symbolsCmd, []string{missingIPSW})
	if err == nil {
		t.Fatal("expected missing file error, got nil")
	}
	if strings.Contains(err.Error(), "only JSONL output is supported") {
		t.Fatalf("symbols command still requires --json: %v", err)
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("err=%v, want missing file validation after default JSONL mode", err)
	}
}

func TestSymbolsExposesOptInFactsFlag(t *testing.T) {
	flag := symbolsCmd.Flags().Lookup("facts")
	if flag == nil {
		t.Fatal("symbols command is missing --facts")
	}
	if flag.DefValue != "false" {
		t.Fatalf("--facts default = %q, want false", flag.DefValue)
	}
}

func TestSymbolsFactsBoardsRequiresFactsJSONAndNoDevice(t *testing.T) {
	flags := symbolsCmd.Flags()
	for _, tc := range []struct {
		name, facts, json, device string
	}{
		{"missing facts", "false", "true", ""},
		{"non JSON", "true", "false", ""},
		{"device selector", "true", "true", "boarda"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for name, value := range map[string]string{"facts-boards": "boarda,boardb", "facts": tc.facts, "json": tc.json, "device": tc.device} {
				flag := flags.Lookup(name)
				oldValue, oldChanged := flag.Value.String(), flag.Changed
				if name == "facts-boards" {
					oldValue = strings.Trim(oldValue, "[]")
				}
				t.Cleanup(func() {
					if err := flag.Value.Set(oldValue); err != nil {
						t.Fatal(err)
					}
					flag.Changed = oldChanged
				})
				if err := flags.Set(name, value); err != nil {
					t.Fatal(err)
				}
			}
			err := symbolsCmd.RunE(symbolsCmd, []string{"missing.ipsw"})
			if err == nil || !strings.Contains(err.Error(), "--facts-boards requires") {
				t.Fatalf("invalid flags reached source I/O: %v", err)
			}
		})
	}
}
