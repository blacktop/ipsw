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

// machoImage returns a synthetic thin executable for arch.
func machoImage(arch MachoArch) []byte {
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
	return data
}

// WriteMacho writes a synthetic thin or universal executable in the given order.
func WriteMacho(t testing.TB, path string, arches ...MachoArch) {
	t.Helper()
	var images [][]byte
	for _, arch := range arches {
		images = append(images, machoImage(arch))
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

// WriteFat64 writes a synthetic fat64 (CA FE BA BF) executable whose slices
// follow one another from offset. Bytes before offset are a hole, so an offset
// past 4 GiB stays cheap on file systems with sparse files.
func WriteFat64(t testing.TB, path string, offset uint64, arches ...MachoArch) {
	t.Helper()
	if len(arches) == 0 {
		t.Fatal("WriteFat64 requires at least one architecture")
	}
	header := binary.BigEndian.AppendUint32(nil, uint32(types.MagicFat64))
	header = binary.BigEndian.AppendUint32(header, uint32(len(arches)))
	var images []byte
	for _, arch := range arches {
		image := machoImage(arch)
		header = binary.BigEndian.AppendUint32(header, uint32(arch.CPU))
		header = binary.BigEndian.AppendUint32(header, uint32(arch.SubCPU))
		header = binary.BigEndian.AppendUint64(header, offset+uint64(len(images)))
		header = binary.BigEndian.AppendUint64(header, uint64(len(image)))
		header = binary.BigEndian.AppendUint64(header, 0) // align, reserved
		images = append(images, image...)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write(header)
	if err == nil {
		_, err = f.WriteAt(images, int64(offset))
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
}
