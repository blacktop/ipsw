package dyld

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/blacktop/go-macho/types"
)

func TestIs64bit(t *testing.T) {
	for _, tt := range []struct {
		magic string
		want  bool
	}{
		{"dyld_v1    i386", false},
		{"dyld_v1  x86_64", true},
		{"dyld_v1 x86_64h", true},
		{"dyld_v1   armv5", false},
		{"dyld_v1   armv6", false},
		{"dyld_v1   armv7", false},
		{"dyld_v1  armv7", false},
		{"dyld_v1   arm64", true},
		{"dyld_v1arm64_32", false},
		{"dyld_v1  arm64e", true},
		{"dyld_v1arm64ex1", true},
	} {
		t.Run(tt.magic, func(t *testing.T) {
			var hdr CacheHeader
			copy(hdr.Magic[:], tt.magic)
			f := &File{Headers: map[types.UUID]CacheHeader{{}: hdr}}
			if got := f.Is64bit(); got != tt.want {
				t.Errorf("Is64bit() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestLocalSymbolNListSize(t *testing.T) {
	for _, tt := range []struct {
		magic string
		size  uint32
	}{
		{"dyld_v1   armv7", 12},
		{"dyld_v1arm64_32", 12},
		{"dyld_v1  arm64e", 16},
	} {
		t.Run(tt.magic, func(t *testing.T) {
			var hdr CacheHeader
			copy(hdr.Magic[:], tt.magic)
			hdr.UUID[0] = 1
			hdr.MappingOffset = uint32(binary.Size(hdr))
			hdr.CodeSignatureOffset, hdr.CodeSignatureSize = uint64(binary.Size(hdr)), 12
			hdr.LocalSymbolsOffset = hdr.CodeSignatureOffset + hdr.CodeSignatureSize
			info := CacheLocalSymbolsInfo{NlistOffset: uint32(binary.Size(CacheLocalSymbolsInfo{})), NlistCount: 2}
			info.StringsOffset, info.StringsSize = info.NlistOffset+info.NlistCount*tt.size, 1
			hdr.LocalSymbolsSize = uint64(info.StringsOffset + info.StringsSize)
			var data bytes.Buffer
			for _, value := range []any{hdr, []byte{0xfa, 0xde, 0x0c, 0xc0, 0, 0, 0, 12, 0, 0, 0, 0}, info, make([]byte, info.NlistCount*tt.size+1)} {
				if err := binary.Write(&data, binary.LittleEndian, value); err != nil {
					t.Fatal(err)
				}
			}
			f, err := NewFile(bytes.NewReader(data.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { f.Close() })
			if got, want := f.LocalSymInfo.NListByteSize, 2*tt.size; got != want {
				t.Errorf("NListByteSize = %d, want %d", got, want)
			}
		})
	}
}
