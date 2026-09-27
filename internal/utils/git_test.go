package utils

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitDiffNoColor(t *testing.T) {
	// Even a host configured to always color git output must honor Color:false.
	t.Setenv("GIT_CONFIG_COUNT", "2")
	t.Setenv("GIT_CONFIG_KEY_0", "color.ui")
	t.Setenv("GIT_CONFIG_VALUE_0", "always")
	t.Setenv("GIT_CONFIG_KEY_1", "color.diff")
	t.Setenv("GIT_CONFIG_VALUE_1", "always")
	t.Setenv("FORCE_COLOR", "1")
	t.Setenv("CLICOLOR_FORCE", "1")
	for _, backend := range []string{"go", "git", "delta", ""} {
		t.Run(backend, func(t *testing.T) {
			if backend == "git" {
				if _, err := exec.LookPath("git"); err != nil {
					t.Skip("git not installed")
				}
			}
			conf := &GitDiffConfig{Tool: backend}
			out, err := GitDiff("before\n", "after\n", conf)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out, "\x1b") || !strings.Contains(out, "before") || !strings.Contains(out, "after") {
				t.Fatalf("expected plain removed/added text, got %q", out)
			}
			if same, err := GitDiff("same\n", "same\n", conf); err != nil || same != "" {
				t.Fatalf("unchanged diff = %q, %v", same, err)
			}
		})
	}
}

func TestGitDiffPlainDeltaBypassesExecutable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "delta"), []byte("#!/bin/sh\nprintf '\\033[31mDELTA INVOKED\\033[0m'\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	for _, backend := range []string{"delta", ""} {
		out, err := GitDiff("one", "two", &GitDiffConfig{Tool: backend})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "DELTA INVOKED") || strings.Contains(out, "\x1b") || !strings.Contains(out, "[-") || !strings.Contains(out, "{+") {
			t.Fatalf("backend %q did not use plain diff: %q", backend, out)
		}
	}
}
