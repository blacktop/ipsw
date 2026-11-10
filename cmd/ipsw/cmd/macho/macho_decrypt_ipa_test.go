package macho

import (
	"bytes"
	"errors"
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
