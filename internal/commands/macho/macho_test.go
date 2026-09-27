package macho

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gomacho "github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

func TestOpenMachOWithoutTerminal(t *testing.T) {
	input, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	stdin, stdout := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = input, output
	defer func() { os.Stdin, os.Stdout = stdin, stdout }()
	for _, tc := range []struct {
		name, arch           string
		count                int
		interactive, wantErr bool
	}{
		{"needs architecture", "", 2, true, true},
		{"explicit architecture", "arm64e", 2, true, false},
		{"invalid architecture", "missing", 2, true, true},
		{"single slice", "", 1, true, false},
		{"explicit first-slice API", "", 2, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var header bytes.Buffer
			if err := binary.Write(&header, binary.BigEndian, []uint32{uint32(types.MagicFat), uint32(tc.count)}); err != nil {
				t.Fatal(err)
			}
			arches := []gomacho.FatArchHeader{
				{CPU: types.CPUAmd64, SubCPU: 3, Offset: 0x100, Size: 32, Align: 8},
				{CPU: types.CPUArm64, SubCPU: 2, Offset: 0x200, Size: 32, Align: 8},
			}
			data := make([]byte, 0x300)
			for _, arch := range arches[:tc.count] {
				if err := binary.Write(&header, binary.BigEndian, arch); err != nil {
					t.Fatal(err)
				}
				thin := types.FileHeader{Magic: types.Magic64, CPU: arch.CPU, SubCPU: arch.SubCPU, Type: types.MH_EXECUTE}
				thin.Put(data[arch.Offset:], binary.LittleEndian)
			}
			copy(data, header.Bytes())
			path := filepath.Join(t.TempDir(), "synthetic-fat")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			m, err := OpenMachONonInteractive(path, tc.arch, tc.interactive)
			if m != nil {
				defer m.Close()
			}
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "--arch") {
					t.Fatalf("expected architecture error, got %v", err)
				}
				return
			}
			if err != nil || m == nil {
				t.Fatalf("open = %v, %v", m, err)
			}
			wantCPU := types.CPUAmd64
			if tc.arch != "" {
				wantCPU = types.CPUArm64
			}
			if m.File.CPU != wantCPU {
				t.Fatalf("CPU = %v, want %v", m.File.CPU, wantCPU)
			}
		})
	}
	data, err := os.ReadFile(output.Name())
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatalf("nonterminal open printed a prompt: %q", data)
	}
}
