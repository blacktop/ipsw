package utils

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
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

func TestGitDiffClosesTempFiles(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	openFDs := func() int {
		entries, err := os.ReadDir("/dev/fd")
		if err != nil {
			t.Skipf("cannot count open descriptors: %v", err)
		}
		return len(entries)
	}
	// Without GC an unclosed os.File keeps its descriptor for the whole loop.
	defer debug.SetGCPercent(debug.SetGCPercent(-1))

	before := openFDs()
	for range 20 {
		if _, err := GitDiff("before\n", "after\n", &GitDiffConfig{Tool: "git"}); err != nil {
			t.Fatal(err)
		}
	}
	if after := openFDs(); after != before {
		t.Fatalf("open descriptors grew from %d to %d across 20 diffs", before, after)
	}
}

func TestGitDiffToolExitStatus(t *testing.T) {
	fakeGit := func(t *testing.T, script string) {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "git"), []byte("#!/bin/sh\n"+script+"\n"), 0755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", dir)
	}
	t.Run("exit 1 means the inputs differ", func(t *testing.T) {
		fakeGit(t, `printf 'h1\nh2\nh3\nh4\n-before\n+after\n'; exit 1`)
		out, err := GitDiff("before\n", "after\n", &GitDiffConfig{Tool: "git"})
		if err != nil || out != "-before\n+after\n" {
			t.Fatalf("GitDiff = %q, %v", out, err)
		}
	})
	t.Run("other exit codes are failures", func(t *testing.T) {
		fakeGit(t, `echo 'fatal: synthetic failure' >&2; exit 128`)
		out, err := GitDiff("before\n", "after\n", &GitDiffConfig{Tool: "git"})
		if err == nil || !strings.Contains(err.Error(), "fatal: synthetic failure") {
			t.Fatalf("GitDiff = %q, %v; want the git failure", out, err)
		}
	})
	t.Run("missing tool is a failure", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		if out, err := GitDiff("before\n", "after\n", &GitDiffConfig{Tool: "git"}); err == nil {
			t.Fatalf("GitDiff = %q, nil; want an error", out)
		}
	})
}

func TestGitDiffIdenticalInputsNeverRunTheTool(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte("#!/bin/sh\necho 'fatal: must not run' >&2\nexit 128\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if out, err := GitDiff("same\n", "same\n", &GitDiffConfig{Tool: "git"}); err != nil || out != "" {
		t.Fatalf("GitDiff = %q, %v; want no diff without running git", out, err)
	}
}
