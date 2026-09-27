//go:build !386

package download

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/pkg/tss"
	"github.com/spf13/viper"
)

func TestProcessTSSResponseStatus(t *testing.T) {
	transportErr := errors.New("synthetic transport failure")
	for _, tt := range []struct {
		name string
		err  error
	}{
		{name: "signed"},
		{name: "unsigned", err: tss.ErrNotSigned},
		{name: "transport failure", err: transportErr},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := processTSSResponse(nil, tt.err, true, "", nil)
			if !errors.Is(err, tt.err) {
				t.Fatalf("got %v; want error matching %v", err, tt.err)
			}
		})
	}
	output := filepath.Join(t.TempDir(), "blobs", "synthetic.shsh")
	if err := processTSSResponse([]byte("unusable"), tss.ErrNotSigned, false, output, nil); !errors.Is(err, tss.ErrNotSigned) {
		t.Fatalf("unsigned blob result = %v", err)
	}
	if _, err := os.Stat(filepath.Dir(output)); !os.IsNotExist(err) {
		t.Fatalf("unsigned response created an output directory: %v", err)
	}
	if err := processTSSResponse([]byte("synthetic blob"), nil, false, output, nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil || string(data) != "synthetic blob" {
		t.Fatalf("saved response = %q, %v", data, err)
	}
}

func TestDownloadTSSNoUpdateUsesExistingCheckout(t *testing.T) {
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "config.yaml")
	if err := os.WriteFile(configPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	previousConfig := viper.ConfigFileUsed()
	viper.SetConfigFile(configPath)
	t.Cleanup(func() { viper.SetConfigFile(previousConfig) })
	for key, value := range map[string]any{
		"download.tss.device": "iPhone99,1", "download.tss.version": "99.0", "download.tss.ecid": uint64(1234),
		"download.tss.no-update": true, "download.tss.usb": false,
	} {
		previous := viper.Get(key)
		viper.Set(key, value)
		t.Cleanup(func() { viper.Set(key, previous) })
	}
	// The missing-checkout diagnostic proves --no-update reached AppleDB;
	// default behavior would attempt a clone instead.
	err := downloadTssCmd.RunE(downloadTssCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "no usable local AppleDB checkout") {
		t.Fatalf("missing checkout: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(configDir, "appledb", "osFiles", "iOS"), 0755); err != nil {
		t.Fatal(err)
	}
	// An empty local catalog finishes its query without requiring a Git repo.
	err = downloadTssCmd.RunE(downloadTssCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "no IPSW found") {
		t.Fatalf("existing checkout: %v", err)
	}
}
