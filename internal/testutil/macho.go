package testutil

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/blacktop/go-macho/types"
)

// MachoArch describes a synthetic slice with an optional XML entitlement blob.
type MachoArch struct {
	CPU          types.CPU
	SubCPU       types.CPUSubtype
	Entitlements string
}

// WriteMacho writes a synthetic thin or universal executable in the given order.
func WriteMacho(t testing.TB, path string, arches ...MachoArch) {
	t.Helper()
	var images [][]byte
	for _, arch := range arches {
		var signature []byte
		var ncmd, cmdsize uint32
		if arch.Entitlements != "" {
			// Embedded signature superblob, one entitlement slot, and its blob.
			for _, word := range []uint32{0xfade0cc0, 28 + uint32(len(arch.Entitlements)), 1, 5, 20, 0xfade7171, 8 + uint32(len(arch.Entitlements))} {
				signature = binary.BigEndian.AppendUint32(signature, word)
			}
			signature = append(signature, arch.Entitlements...)
			ncmd, cmdsize = 1, 16
		}
		var data []byte
		// mach_header_64, MH_EXECUTE.
		for _, word := range []uint32{0xfeedfacf, uint32(arch.CPU), uint32(arch.SubCPU), 2, ncmd, cmdsize, 0, 0} {
			data = binary.LittleEndian.AppendUint32(data, word)
		}
		if len(signature) > 0 {
			// LC_CODE_SIGNATURE points just past the header and load command.
			for _, word := range []uint32{0x1d, 16, 48, uint32(len(signature))} {
				data = binary.LittleEndian.AppendUint32(data, word)
			}
			data = append(data, signature...)
		}
		images = append(images, data)
	}
	if len(images) == 0 {
		t.Fatal("WriteMacho requires at least one architecture")
	}
	data := images[0]
	if len(images) > 1 {
		data = binary.BigEndian.AppendUint32(nil, 0xcafebabe)
		data = binary.BigEndian.AppendUint32(data, uint32(len(images)))
		offset := uint32(8 + 20*len(images))
		for idx, arch := range arches {
			for _, word := range []uint32{uint32(arch.CPU), uint32(arch.SubCPU), offset, uint32(len(images[idx])), 0} {
				data = binary.BigEndian.AppendUint32(data, word)
			}
			offset += uint32(len(images[idx]))
		}
		for _, image := range images {
			data = append(data, image...)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatal(err)
	}
}
