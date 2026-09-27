package utils

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveTempDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "staging")
	if err := os.MkdirAll(filepath.Join(dir, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	bodyErr := errors.New("body failed")
	retErr := bodyErr
	RemoveTempDir(dir, &retErr)
	if !errors.Is(retErr, bodyErr) || retErr.Error() != bodyErr.Error() {
		t.Fatalf("successful removal changed the caller's error: %v", retErr)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("directory still present: %v", err)
	}
	retErr = nil
	RemoveTempDir(dir, &retErr)
	if retErr != nil {
		t.Fatalf("removing an absent directory reported %v", retErr)
	}
}
