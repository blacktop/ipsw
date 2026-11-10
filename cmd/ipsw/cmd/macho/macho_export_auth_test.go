//go:build darwin || linux

package macho

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blacktop/ipsw/pkg/fairplay"
)

func authorizationFixture() []byte {
	data := make([]byte, 26)
	copy(data, []byte{'F', 'P', 'A', 'U', 'T', 'H', 0, 0})
	binary.BigEndian.PutUint32(data[8:12], 1)
	binary.BigEndian.PutUint32(data[12:16], 4)
	copy(data[16:22], "FAKEID")
	copy(data[22:], "TEST")
	return data
}

func openFixtureDirectory(t *testing.T, output string) *os.File {
	t.Helper()
	directory, _, err := openAuthorizationDirectory(output)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = directory.Close() })
	return directory
}

func TestWriteAuthorizationPrivateAndExclusive(t *testing.T) {
	output := filepath.Join(t.TempDir(), "authorization")
	data := authorizationFixture()
	directory, created, err := openAuthorizationDirectory(output)
	if err != nil || !created {
		t.Fatalf("new directory was not created: %v, %v", created, err)
	}
	defer directory.Close()
	if err := writeAuthorization(directory, data); err != nil {
		t.Fatal(err)
	}
	for path, mode := range map[string]os.FileMode{output: 0700, filepath.Join(output, authorizationFilename): 0600} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("incorrect permissions for %s: %v, %v", path, info, err)
		}
	}
	changed := authorizationFixture()
	changed[len(changed)-1] = 'X'
	if err := writeAuthorization(directory, changed); err == nil {
		t.Fatal("existing file was accepted")
	}
	if _, _, err := openAuthorizationDirectory(output); err == nil {
		t.Fatal("directory holding an authorization file passed the preflight")
	}
	got, err := os.ReadFile(filepath.Join(output, authorizationFilename))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("existing authorization was changed")
	}
}

func TestOpenAuthorizationDirectoryReusesPrivateDirectory(t *testing.T) {
	output := filepath.Join(t.TempDir(), "authorization")
	if err := os.Mkdir(output, 0700); err != nil {
		t.Fatal(err)
	}
	directory, created, err := openAuthorizationDirectory(output)
	if err != nil || created {
		t.Fatalf("existing private directory was not reused: %v, %v", created, err)
	}
	_ = directory.Close()
	missingParent := filepath.Join(t.TempDir(), "missing", "authorization")
	if _, _, err := openAuthorizationDirectory(missingParent); err == nil {
		t.Fatal("directory under a missing parent was accepted")
	}
}

func TestWriteAuthorizationFailurePreservesReplacement(t *testing.T) {
	output := filepath.Join(t.TempDir(), "authorization")
	path := filepath.Join(output, authorizationFilename)
	replacement := []byte("synthetic replacement")
	injected := errors.New("synthetic write failure")
	directory := openFixtureDirectory(t, output)
	err := writeAuthorizationWith(directory, authorizationFixture(), func(file *os.File, data []byte) (int, error) {
		if _, err := file.Write(data[:2]); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path, path+".original"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, replacement, 0600); err != nil {
			t.Fatal(err)
		}
		return 2, injected
	})
	if err == nil || err.Error() != "could not write the authorization file" {
		t.Fatalf("first write failure was lost: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, replacement) {
		t.Fatalf("concurrent replacement was removed or changed: %q, %v", got, err)
	}
}

func TestWriteAuthorizationRejectsUnsafeDirectory(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openAuthorizationDirectory(link); err == nil {
		t.Fatal("symlink directory was accepted")
	}
	if err := os.Chmod(target, 0755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openAuthorizationDirectory(target); err == nil {
		t.Fatal("public directory was accepted")
	}
}

func TestWriteAuthorizationRejectsInvalidSnapshot(t *testing.T) {
	output := filepath.Join(t.TempDir(), "authorization")
	truncated := authorizationFixture()
	err := writeAuthorization(openFixtureDirectory(t, output), truncated[:len(truncated)-1])
	if err == nil {
		t.Fatal("snapshot with a mismatched length was accepted")
	}
	if _, err := os.Stat(filepath.Join(output, authorizationFilename)); !os.IsNotExist(err) {
		t.Fatalf("unexpected authorization file: %v", err)
	}
}

func TestCollectAuthorizationBoundedAndObserved(t *testing.T) {
	for _, mode := range []string{"success", "failed", "oversized", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			timeout := 5 * time.Second
			if mode == "timeout" {
				timeout = 50 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAuthorizationHelperProcess$")
			command.Env = []string{"IPSW_TEST_EXPORT_HELPER=" + mode}
			payload, err := collectAuthorization(ctx, command, cancel)
			if mode == "success" {
				if err != nil || !bytes.Equal(payload, authorizationFixture()) {
					t.Fatalf("unexpected capture: %d bytes, %v", len(payload), err)
				}
				return
			}
			if err == nil || payload != nil {
				t.Fatalf("expected bounded failure, got %d bytes, %v", len(payload), err)
			}
			if strings.Contains(err.Error(), "SYNTHETIC_PRIVATE") {
				t.Fatal("helper payload leaked in error")
			}
			if command.ProcessState == nil {
				t.Fatal("child was not waited for")
			}
		})
	}
}

func TestAuthorizationHelperProcess(t *testing.T) {
	mode := os.Getenv("IPSW_TEST_EXPORT_HELPER")
	if mode == "" {
		return
	}
	switch mode {
	case "success":
		_, _ = os.Stdout.Write(authorizationFixture())
	case "failed":
		_, _ = os.Stdout.Write(authorizationFixture())
		_, _ = os.Stderr.WriteString("SYNTHETIC_PRIVATE")
		os.Exit(3)
	case "oversized":
		_, _ = os.Stdout.Write(make([]byte, fairplay.AuthorizationMaxBytes+1))
	case "timeout":
		time.Sleep(time.Minute)
	}
	os.Exit(0)
}
