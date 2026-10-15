package macho

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/blacktop/go-macho/types"
)

func TestMachoA2oMappingErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		memsz   uint64
		offset  uint64
		address uint64
		wantErr bool
	}{
		{"mapped", 0x1000, 0, 0x1234, false},
		{"unmapped", 0x1000, 0, ^uint64(0), true},
		{"overflow", 0x8000000000002000, 0x7ffffffffffffc00, 0x8000000000001581, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var data bytes.Buffer
			header := types.FileHeader{Magic: types.Magic64, CPU: types.CPUArm64,
				Type: types.MH_EXECUTE, NCommands: 1, SizeCommands: 72}
			seg := types.Segment64{LoadCmd: types.LC_SEGMENT_64, Len: 72,
				Addr: 0x1000, Memsz: tc.memsz, Offset: tc.offset, Filesz: 0x100}
			copy(seg.Name[:], "__DATA")
			for _, value := range []any{header, seg} {
				if err := binary.Write(&data, binary.LittleEndian, value); err != nil {
					t.Fatal(err)
				}
			}
			data.Write(make([]byte, 0x100))
			path := filepath.Join(t.TempDir(), "mapping.macho")
			if err := os.WriteFile(path, data.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			err := machoA2oCmd.RunE(machoA2oCmd, []string{path, fmt.Sprintf("%#x", tc.address)})
			if (err != nil) != tc.wantErr {
				t.Fatalf("a2o returned %v, want error: %v", err, tc.wantErr)
			}
		})
	}
}
