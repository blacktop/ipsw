package kernelcache

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blacktop/go-macho/types"
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
	// A sibling board can use the same basename in another directory. A
	// manifest path must not fall back to matching that sibling by basename.
	out, err = ExtractWithInfo(&info.Info{}, ipswPath, t.TempDir(), "OtherBoard/kernelcache.release.other")
	if err != nil || len(out) != 0 {
		t.Fatalf("ExtractWithInfo(sibling path) = %v, %v; want no matches", out, err)
	}

	_, err = ExtractWithInfo(&info.Info{}, ipswPath, t.TempDir(), "Firmware/kernelcache.release.other")
	if err == nil || !strings.Contains(err.Error(), "failed to parse im4p kernelcache data") {
		t.Fatalf("ExtractWithInfo(matching target) error = %v, want IMG4 parse error", err)
	}
}

func TestExtractKernelcachesReportsOwnedCleanupFailure(t *testing.T) {
	ip := filepath.Join(t.TempDir(), "empty.ipsw")
	f, err := os.Create(ip)
	if err != nil {
		t.Fatal(err)
	}
	if err := zip.NewWriter(f).Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("injected removal failure")
	removed := false
	_, err = extractKernelcachesWithCleanup(&info.Info{}, ip, t.TempDir(), nil, func(path string) error {
		removed = true
		return errors.Join(os.RemoveAll(path), wantErr)
	})
	if !removed || !errors.Is(err, wantErr) {
		t.Fatalf("cleanup failure lost: removed=%t err=%v", removed, err)
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

func TestThinSingleSliceDropsTrailingPadding(t *testing.T) {
	thin := make([]byte, types.FileHeaderSize64) // an MH_FILESET with no load commands
	(&types.FileHeader{
		Magic: types.Magic64, CPU: types.CPUArm64, SubCPU: types.CPUSubtypeArm64E, Type: types.MH_FILESET,
	}).Put(thin, binary.LittleEndian)
	const offset = 0x1000
	fat := make([]byte, offset)
	for idx, word := range []uint32{
		types.MagicFat.Int(), 1, // fat_header
		uint32(types.CPUArm64), uint32(types.CPUSubtypeArm64E), offset, uint32(len(thin)), 12, // fat_arch
	} {
		binary.BigEndian.PutUint32(fat[idx*4:], word)
	}
	fat = append(fat, thin...)
	fat = append(fat, bytes.Repeat([]byte{0xaa}, 0x4000)...)

	got, err := thinSingleSlice(fat)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, thin) {
		t.Fatalf("got %#x bytes, want the %#x-byte slice without the padding after it", len(got), len(thin))
	}
	if got, err := thinSingleSlice(thin); err != nil || !bytes.Equal(got, thin) {
		t.Fatalf("thin kernelcache: got %#x bytes, %v; want it unchanged", len(got), err)
	}
}
