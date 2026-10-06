package download

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/spf13/viper"
)

func TestDownloadKDKNoninteractiveRequiresSelectorBeforeRequest(t *testing.T) {
	input, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	previousInput := os.Stdin
	os.Stdin = input
	t.Cleanup(func() { os.Stdin = previousInput })
	for key, value := range map[string]any{
		"download.kdk.host": false, "download.kdk.build": "", "download.kdk.latest": false, "download.kdk.all": false,
		"download.kdk.clean": false,
	} {
		previous := viper.Get(key)
		viper.Set(key, value)
		t.Cleanup(func() { viper.Set(key, previous) })
	}
	if err := downloadKdkCmd.RunE(downloadKdkCmd, nil); err == nil || !strings.Contains(err.Error(), "--host, --build, --latest, or --all") {
		t.Fatalf("expected local selector error, got %v", err)
	}
}

func TestDownloadKDKCleanRequiresInstallBeforeRequest(t *testing.T) {
	for key, value := range map[string]any{
		"download.kdk.clean": true, "download.kdk.install": false, "download.kdk.latest": true,
	} {
		previous := viper.Get(key)
		viper.Set(key, value)
		t.Cleanup(func() { viper.Set(key, previous) })
	}
	if err := downloadKdkCmd.RunE(downloadKdkCmd, nil); err == nil || !strings.Contains(err.Error(), "--clean requires --install") {
		t.Fatalf("expected local flag error, got %v", err)
	}
}

func TestInstallKDKDownload(t *testing.T) {
	installError := errors.New("synthetic install failure")
	for _, tt := range []struct {
		name        string
		clean       bool
		interactive bool
		installErr  error
		answer      bool
		promptError error
		wantRemoved bool
	}{
		{name: "unattended"},
		{name: "clean unattended", clean: true, wantRemoved: true},
		{name: "failed clean installation", clean: true, interactive: true, installErr: installError},
		{name: "declined", interactive: true},
		{name: "accepted", interactive: true, answer: true, wantRemoved: true},
		{name: "interrupted", interactive: true, answer: true, promptError: terminal.InterruptErr},
	} {
		t.Run(tt.name, func(t *testing.T) {
			destName := filepath.Join(t.TempDir(), "KDK.pkg")
			if err := os.WriteFile(destName, []byte("synthetic KDK"), 0600); err != nil {
				t.Fatal(err)
			}
			prompted := false
			err := installKDKDownload(destName, tt.clean, tt.interactive, func(name string) error {
				if name != destName {
					t.Fatalf("unexpected install path %q", name)
				}
				return tt.installErr
			}, func(prompt *survey.Confirm, answer *bool) error {
				prompted = true
				if prompt.Default || !strings.Contains(prompt.Message, destName) {
					t.Fatalf("unsafe cleanup prompt: %+v", prompt)
				}
				*answer = tt.answer
				return tt.promptError
			})
			wantErr := tt.installErr
			if wantErr == nil {
				wantErr = tt.promptError
			}
			wantPrompt := tt.installErr == nil && !tt.clean && tt.interactive
			if !errors.Is(err, wantErr) || prompted != wantPrompt {
				t.Fatalf("err=%v prompted=%v", err, prompted)
			}
			if _, err := os.Stat(destName); tt.wantRemoved {
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("expected package removal, got %v", err)
				}
			} else if err != nil {
				t.Fatalf("expected package to be kept: %v", err)
			}
		})
	}
}

func TestInstallKDKDownloadReportsCleanupFailure(t *testing.T) {
	destName := filepath.Join(t.TempDir(), "KDK.pkg")
	if err := os.WriteFile(destName, []byte("synthetic KDK"), 0600); err != nil {
		t.Fatal(err)
	}
	err := installKDKDownload(destName, true, false, os.Remove, nil)
	if !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), "failed to delete") {
		t.Fatalf("expected cleanup failure, got %v", err)
	}
}
