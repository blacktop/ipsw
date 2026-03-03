package ota

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/blacktop/ipsw/pkg/ota/types"
)

func writeAEAKeyDB(t *testing.T, entries []types.AEAKeyEntry) string {
	t.Helper()

	data, err := json.Marshal(entries)
	if err != nil {
		t.Fatalf("failed to marshal key db: %v", err)
	}

	f, err := os.CreateTemp("", "ota-keys-*.json")
	if err != nil {
		t.Fatalf("failed to create temp key db: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Remove(f.Name())
	})

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		t.Fatalf("failed to write key db: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close key db: %v", err)
	}

	return f.Name()
}

func TestResolveAEAKeyPrefersExplicitKeyOverDatabase(t *testing.T) {
	dbPath := writeAEAKeyDB(t, []types.AEAKeyEntry{
		{
			Filename: "iPhone18,1_26.4_23E5218e_Restore.ipsw",
			Key:      "db-key",
		},
	})

	otaPath := filepath.Join("/tmp", "iPhone18,1_26.4_23E5218e_Restore.ipsw")
	conf := ResolveAEAKey(otaPath, dbPath, "explicit-key", false)

	if conf.SymmetricKey != "explicit-key" {
		t.Fatalf("expected explicit key to win, got %q", conf.SymmetricKey)
	}
}

func TestResolveAEAKeyUsesDatabaseWhenExplicitKeyMissing(t *testing.T) {
	dbPath := writeAEAKeyDB(t, []types.AEAKeyEntry{
		{
			Filename: "iPhone18,1_26.4_23E5218e_Restore.ipsw",
			Key:      "db-key",
		},
	})

	otaPath := filepath.Join("/tmp", "iPhone18,1_26.4_23E5218e_Restore.ipsw")
	conf := ResolveAEAKey(otaPath, dbPath, "", false)

	if conf.SymmetricKey != "db-key" {
		t.Fatalf("expected database key, got %q", conf.SymmetricKey)
	}
}
