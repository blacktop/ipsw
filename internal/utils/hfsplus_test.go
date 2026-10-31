package utils

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/blacktop/go-apfs/pkg/disk/dmg"
	"github.com/blacktop/ipsw/internal/testutil"
)

func TestMountHFSPlusImages(t *testing.T) {
	for _, container := range []bool{false, true} {
		for _, fail := range []bool{false, true} {
			name := "raw"
			if container {
				name = "compressed UDIF"
			}
			if fail {
				name += "/mount failure"
			}
			t.Run(name, func(t *testing.T) {
				root := t.TempDir()
				t.Setenv("TMPDIR", t.TempDir())
				plain := make([]byte, 4*512)
				copy(plain[1024:], "HX")
				copy(plain[1536:], "synthetic filesystem")
				data := plain
				if container {
					data = testutil.UDIFImage(t, plain)
				}
				image := filepath.Join(root, "image.dmg")
				if err := os.WriteFile(image, data, 0600); err != nil {
					t.Fatal(err)
				}
				mountPoint := filepath.Join(root, "mount")
				var mountedImage string
				err := mountHFSPlus(image, mountPoint, func(cmd *exec.Cmd) ([]byte, error) {
					if len(cmd.Args) != 7 {
						t.Fatalf("unexpected mount arguments: %q", cmd.Args)
					}
					mountedImage = cmd.Args[5]
					want := []string{"mount", "-t", "hfsplus", "-o", "ro,loop", mountedImage, mountPoint}
					if !reflect.DeepEqual(cmd.Args, want) {
						t.Fatalf("mount = %q, want %q", cmd.Args, want)
					}
					if (mountedImage != image) != container {
						t.Fatalf("wrong backing image: %s", mountedImage)
					}
					if filepath.Dir(mountedImage) != root {
						t.Fatalf("raw image %s was not staged beside %s", mountedImage, image)
					}
					if got, err := os.ReadFile(mountedImage); err != nil || !bytes.Equal(got, plain) {
						t.Fatalf("mount did not receive the raw filesystem: %v", err)
					}
					if fail {
						return []byte("synthetic mount failure"), errors.New("exit status 32")
					}
					return []byte("synthetic warning"), nil
				})
				if mountedImage == "" || (err != nil) != fail {
					t.Fatalf("mounted image=%q, error=%v", mountedImage, err)
				}
				if fail && !strings.Contains(err.Error(), "synthetic mount failure") {
					t.Fatalf("lost command output: %v", err)
				}
				if container {
					if _, err := os.Stat(mountedImage); !os.IsNotExist(err) {
						t.Fatalf("temporary image remains: %v", err)
					}
				}
				if got, err := os.ReadFile(image); err != nil || !bytes.Equal(got, data) {
					t.Fatalf("source image changed: %v", err)
				}
			})
		}
	}
}

func TestHFSPlusImageRejectsResourceFork(t *testing.T) {
	var image bytes.Buffer
	image.Write(make([]byte, 512))
	footer := dmg.UDIFResourceFile{
		Signature: [4]byte{'k', 'o', 'l', 'y'}, Version: 4, HeaderSize: 512,
		DataForkLength: 512, RsrcForkOffset: 1, RsrcForkLength: 1, SectorCount: 1,
	}
	if err := binary.Write(&image, binary.BigEndian, footer); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "resource-fork.dmg")
	if err := os.WriteFile(path, image.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := hfsPlusImage(path); err == nil || !strings.Contains(err.Error(), "no supported plist block map") {
		t.Fatalf("unsupported resource fork was not rejected: %v", err)
	}
}

func TestHFSPlusImageReportsProbeFailure(t *testing.T) {
	plain := make([]byte, 4*512)
	copy(plain[1024:], "H+")
	data := testutil.UDIFImage(t, plain)
	// Corrupt the zlib stream so decoding the only partition fails.
	for i := 2; i < 12; i++ {
		data[i] ^= 0xff
	}
	path := filepath.Join(t.TempDir(), "corrupt.dmg")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	_, err := hfsPlusImage(path)
	if err == nil || !strings.Contains(err.Error(), "no HFS+ partition found") ||
		!strings.Contains(err.Error(), `partition "synthetic partition"`) {
		t.Fatalf("decode failure was hidden: %v", err)
	}
}
