package kernelcache

import (
	"archive/zip"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/blacktop/ipsw/pkg/info"
)

func TestExtractWithInfoTargetsOnlyNamedKernelcache(t *testing.T) {
	ipswPath := filepath.Join(t.TempDir(), "test.ipsw")
	f, err := os.Create(ipswPath)
	if err != nil {
		t.Fatalf("Create(%s): %v", ipswPath, err)
	}
	zw := zip.NewWriter(f)
	member, err := zw.Create("Firmware/kernelcache.release.other")
	if err != nil {
		t.Fatalf("Create kernelcache member: %v", err)
	}
	if _, err := member.Write([]byte("deliberately invalid IMG4")); err != nil {
		t.Fatalf("Write kernelcache member: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("Close zip: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close IPSW: %v", err)
	}

	out, err := ExtractWithInfo(&info.Info{}, ipswPath, t.TempDir(), "Firmware/kernelcache.release.target")
	if err != nil {
		t.Fatalf("ExtractWithInfo(nonmatching target): %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("ExtractWithInfo(nonmatching target) extracted %d members, want 0", len(out))
	}

	_, err = ExtractWithInfo(&info.Info{}, ipswPath, t.TempDir(), "Firmware/kernelcache.release.other")
	if err == nil || !strings.Contains(err.Error(), "failed to parse im4p kernelcache data") {
		t.Fatalf("ExtractWithInfo(matching target) error = %v, want IMG4 parse error", err)
	}
}

func TestParseImg4DataRejectsEncryptedKernelcache(t *testing.T) {
	payload, err := img4.CreatePayload(&img4.CreatePayloadConfig{
		Type:        img4.IM4P_KERNELCACHE,
		Version:     "KernelCacheBuilder-test",
		Data:        []byte("encrypted kernel payload"),
		Compression: "none",
		Keybags: []img4.Keybag{
			{
				IV:  []byte("1234567890abcdef"),
				Key: []byte("1234567890abcdef1234567890abcdef"),
			},
		},
	})
	if err != nil {
		t.Fatalf("CreatePayload() error = %v", err)
	}

	data, err := payload.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	_, err = ParseImg4Data(data)
	if !errors.Is(err, ErrEncryptedKernelCache) {
		t.Fatalf("ParseImg4Data() error = %v, want %v", err, ErrEncryptedKernelCache)
	}
}
