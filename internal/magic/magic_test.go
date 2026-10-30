package magic

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/blacktop/ipsw/pkg/img3"
)

func TestIsImg3(t *testing.T) {
	for _, magic := range []string{"3gmI", "Img3", "test"} {
		t.Run(magic, func(t *testing.T) {
			data := make([]byte, binary.Size(img3.Header{}))
			copy(data, magic)
			path := filepath.Join(t.TempDir(), "payload")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			got, err := IsImg3(path)
			if err != nil || got != (magic == "3gmI") {
				t.Fatalf("IsImg3 = %t, %v", got, err)
			}
		})
	}
}

func TestIsHFSPlus(t *testing.T) {
	for _, signature := range []string{"H+", "HX", "xx"} {
		t.Run(signature, func(t *testing.T) {
			data := make([]byte, 1026)
			copy(data[1024:], signature)
			path := filepath.Join(t.TempDir(), "filesystem")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			got, err := IsHFSPlus(path)
			if err != nil || got != (signature != "xx") {
				t.Fatalf("IsHFSPlus = %t, %v", got, err)
			}
		})
	}
}
