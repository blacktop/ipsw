package macho

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/pkg/fairplay"
)

func TestDecryptIPACommand(t *testing.T) {
	called := false
	command := newMachoDecryptIPACmd(func(ipa, auth, output string) (fairplay.Result, error) {
		called = true
		if ipa != "fixture.ipa" || auth != "fixture.fpauth" || output != "new-output" {
			t.Fatalf("unexpected arguments: %q, %q, %q", ipa, auth, output)
		}
		return fairplay.Result{ParentSyncUnconfirmed: true}, nil
	})
	var stdout, stderr bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetArgs([]string{"fixture.ipa", "--auth", "fixture.fpauth", "--output", "new-output"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if !called || !strings.Contains(stdout.String(), "new-output") || !strings.Contains(stderr.String(), "durability") {
		t.Fatalf("missing result: %q / %q", stdout.String(), stderr.String())
	}
}

func TestDecryptIPACommandRequiresExplicitInputs(t *testing.T) {
	command := newMachoDecryptIPACmd(func(_, _, _ string) (fairplay.Result, error) {
		t.Fatal("backend must not run")
		return fairplay.Result{}, nil
	})
	command.SetOut(&bytes.Buffer{})
	command.SetErr(&bytes.Buffer{})
	for _, args := range [][]string{
		{"fixture.ipa", "--auth", "fixture.fpauth"},
		{"fixture.ipa", "--auth", "", "--output", "new-output"},
	} {
		command.SetArgs(args)
		if err := command.Execute(); err == nil {
			t.Fatalf("missing output or empty auth must fail: %q", args)
		}
	}
}

func TestDecryptIPACommandPreservesBackendFailure(t *testing.T) {
	command := newMachoDecryptIPACmd(func(_, _, _ string) (fairplay.Result, error) { return fairplay.Result{}, fairplay.ErrLicenseAbsent })
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&bytes.Buffer{})
	command.SetArgs([]string{"fixture.ipa", "--auth", "fixture.fpauth", "--output", "new-output"})
	if err := command.Execute(); !errors.Is(err, fairplay.ErrLicenseAbsent) {
		t.Fatalf("unexpected error: %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatal("failed decryption printed success")
	}
}

// newDirectoryEngine writes one result file the way the engine does: only into a new directory.
func newDirectoryEngine(content string) decryptIPAFunc {
	return func(_, _, output string) (fairplay.Result, error) {
		if err := os.Mkdir(output, 0o700); err != nil {
			return fairplay.Result{}, fairplay.ErrOfflineProcessing
		}
		return fairplay.Result{}, os.WriteFile(filepath.Join(output, "repacked.ipa"), []byte(content), 0o400)
	}
}

func runDecryptIPA(t *testing.T, decrypt decryptIPAFunc, output string) error {
	t.Helper()
	command := newMachoDecryptIPACmd(decrypt)
	command.SetOut(&bytes.Buffer{})
	command.SetErr(&bytes.Buffer{})
	command.SetArgs([]string{"fixture.ipa", "--auth", "fixture.fpauth", "--output", output})
	return command.Execute()
}

func outputNames(t *testing.T, output string) string {
	t.Helper()
	entries, err := os.ReadDir(output)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(entries))
	for i, entry := range entries {
		names[i] = entry.Name()
	}
	return strings.Join(names, ",")
}

func TestDecryptIPACommandRerunReplacesEarlierResult(t *testing.T) {
	output := filepath.Join(t.TempDir(), "decrypted")
	if err := runDecryptIPA(t, newDirectoryEngine("first"), output); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(output, "notes.txt"), []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runDecryptIPA(t, newDirectoryEngine("second"), output); err != nil {
		t.Fatal(err)
	}
	result, err := os.ReadFile(filepath.Join(output, "repacked.ipa"))
	if err != nil || string(result) != "second" {
		t.Fatalf("result = %q, %v; want the rerun's result", result, err)
	}
	if names := outputNames(t, output); names != "notes.txt,repacked.ipa" {
		t.Fatalf("output holds %q; want the result beside the untouched file", names)
	}
}

func TestDecryptIPACommandFailedRerunKeepsEarlierResult(t *testing.T) {
	output := filepath.Join(t.TempDir(), "decrypted")
	if err := runDecryptIPA(t, newDirectoryEngine("first"), output); err != nil {
		t.Fatal(err)
	}
	failing := func(_, _, _ string) (fairplay.Result, error) {
		return fairplay.Result{}, fairplay.ErrLicenseAbsent
	}
	if err := runDecryptIPA(t, failing, output); !errors.Is(err, fairplay.ErrLicenseAbsent) {
		t.Fatalf("unexpected error: %v", err)
	}
	result, err := os.ReadFile(filepath.Join(output, "repacked.ipa"))
	if err != nil || string(result) != "first" || outputNames(t, output) != "repacked.ipa" {
		t.Fatalf("earlier result changed: %q, %v, %q", result, err, outputNames(t, output))
	}
}

func TestDecryptIPACommandRejectsFileOutput(t *testing.T) {
	output := filepath.Join(t.TempDir(), "decrypted")
	if err := os.WriteFile(output, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err := runDecryptIPA(t, newDirectoryEngine("unused"), output)
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptIPACommandDefaultsAuthorization(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	want := filepath.Join(home, ".config", "ipsw", "fairplay", "authorization.fpauth")
	command := newMachoDecryptIPACmd(func(_, auth, _ string) (fairplay.Result, error) {
		if auth != want {
			t.Fatalf("authorization = %q, want %q", auth, want)
		}
		return fairplay.Result{}, nil
	})
	command.SetOut(&bytes.Buffer{})
	command.SetErr(&bytes.Buffer{})
	command.SetArgs([]string{"fixture.ipa", "--output", "new-output"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
}
