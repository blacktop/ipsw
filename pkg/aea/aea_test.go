package aea

import (
	"bytes"
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func metadataEntry(key, value string) []byte {
	entry := binary.LittleEndian.AppendUint32(nil, uint32(5+len(key)+len(value)))
	entry = append(entry, key...)
	entry = append(entry, 0)
	return append(entry, value...)
}

func TestInfo(t *testing.T) {
	valid := append(metadataEntry("first", "one"), metadataEntry("second", "two")...)
	for _, tc := range []struct {
		name     string
		auth     []byte
		declared uint32
		wantErr  bool
	}{
		{name: "empty"},
		{name: "key_value", auth: valid},
		{name: "partial_length", auth: []byte{1}, wantErr: true},
		{name: "zero_length", auth: make([]byte, 4), wantErr: true},
		{name: "short_length", auth: binary.LittleEndian.AppendUint32(nil, 3), wantErr: true},
		{name: "overrun", auth: binary.LittleEndian.AppendUint32(nil, math.MaxUint32), wantErr: true},
		{name: "missing_separator", auth: append(binary.LittleEndian.AppendUint32(nil, 5), 'x'), wantErr: true},
		{name: "truncated_table", auth: valid[:len(valid)-1], declared: uint32(len(valid)), wantErr: true},
		{name: "oversized_table", declared: math.MaxUint32, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			length := uint32(len(tc.auth))
			if tc.declared != 0 {
				length = tc.declared
			}
			var data bytes.Buffer
			if err := binary.Write(&data, binary.LittleEndian, Header{Magic: [4]byte{'A', 'E', 'A', '1'}, AuthDataLength: length}); err != nil {
				t.Fatal(err)
			}
			data.Write(tc.auth)
			name := filepath.Join(t.TempDir(), "synthetic.aea")
			if err := os.WriteFile(name, data.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := Info(name)
			if tc.wantErr {
				if err == nil {
					t.Fatal("accepted invalid metadata")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(tc.auth) == 0 {
				if len(got) != 0 {
					t.Fatalf("unexpected metadata: %v", got)
				}
			} else if len(got) != 2 || string(got["first"]) != "one" || string(got["second"]) != "two" {
				t.Fatalf("unexpected metadata: %v", got)
			}
		})
	}
}
