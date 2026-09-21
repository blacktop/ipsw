package dyld

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSlideInfoRejectsZeroPageSize(t *testing.T) {
	for _, version := range []uint32{2, 3, 4, 5} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			data := slideHeaderFixture(t, version)
			f := fileReading(data)
			mapping := &CacheMappingWithSlideInfo{}
			if err := f.GetSlideInfo(f.UUID, mapping); err != nil {
				t.Fatal(err)
			}
			binary.LittleEndian.PutUint32(data[4:], 0)
			err := f.GetSlideInfo(f.UUID, mapping)
			if err == nil || !strings.Contains(err.Error(), "invalid slide info page size: 0") {
				t.Fatalf("GetSlideInfo() = %v, want invalid page size error", err)
			}
			if got := f.SlideInfo.GetPageSize(); got != 0x1000 {
				t.Fatalf("invalid header replaced the previous slide info: page size = %#x", got)
			}
		})
	}
}

func TestSlideInfoV1(t *testing.T) {
	f := fileReading(slideHeaderFixture(t, 1))
	if err := f.GetSlideInfo(f.UUID, &CacheMappingWithSlideInfo{}); err != nil {
		t.Fatal(err)
	}
	if got := f.SlideInfo.GetPageSize(); got != 4096 {
		t.Fatalf("page size = %d, want 4096", got)
	}
}

func TestOpenRejectsInvalidSlideInfo(t *testing.T) {
	for _, layout := range []string{"legacy", "modern"} {
		versions := []uint32{2}
		if layout == "modern" {
			versions = []uint32{2, 3, 4, 5}
		}
		for _, version := range versions {
			for _, corrupt := range []string{"valid", "zero page size", "truncated header"} {
				t.Run(fmt.Sprintf("%s/v%d/%s", layout, version, corrupt), func(t *testing.T) {
					info := slideHeaderFixture(t, version)
					hdr := CacheHeader{MappingCount: 1, MappingWithSlideCount: 1, CodeSignatureSize: 12}
					copy(hdr.Magic[:], "dyld_v1  arm64e")
					hdr.UUID[0] = 1
					hdr.MappingOffset = uint32(binary.Size(hdr))
					hdr.MappingWithSlideOffset = hdr.MappingOffset + uint32(binary.Size(CacheMappingInfo{}))
					hdr.CodeSignatureOffset = uint64(hdr.MappingWithSlideOffset) + uint64(binary.Size(CacheMappingAndSlideInfo{}))
					mapping := CacheMappingAndSlideInfo{
						Address: 0x180000000, Size: 0x1000, InitProt: 3, MaxProt: 3,
						SlideInfoOffset: hdr.CodeSignatureOffset + hdr.CodeSignatureSize,
						SlideInfoSize:   uint64(len(info)),
					}
					if layout == "legacy" {
						hdr.SlideInfoOffsetUnused = mapping.SlideInfoOffset
						hdr.SlideInfoSizeUnused = mapping.SlideInfoSize
					}
					switch corrupt {
					case "zero page size":
						binary.LittleEndian.PutUint32(info[4:], 0)
					case "truncated header":
						info = info[:8]
					}
					var data bytes.Buffer
					for _, value := range []any{hdr, CacheMappingInfo{
						Address: mapping.Address, Size: mapping.Size, InitProt: 3, MaxProt: 3,
					}, mapping} {
						if err := binary.Write(&data, binary.LittleEndian, value); err != nil {
							t.Fatal(err)
						}
					}
					if err := binary.Write(&data, binary.BigEndian, fakeCodeSignature); err != nil {
						t.Fatal(err)
					}
					data.Write(info)
					path := filepath.Join(t.TempDir(), "dyld_shared_cache_arm64e")
					if err := os.WriteFile(path, data.Bytes(), 0o600); err != nil {
						t.Fatal(err)
					}
					f, err := Open(path)
					if f != nil {
						f.Close()
					}
					switch corrupt {
					case "valid":
						if err != nil {
							t.Fatalf("Open() = %v, want valid slide header", err)
						}
					case "zero page size":
						if err == nil || !strings.Contains(err.Error(), "invalid slide info page size: 0") {
							t.Fatalf("Open() = %v, want invalid page size error", err)
						}
					case "truncated header":
						if err == nil || !strings.Contains(err.Error(), io.ErrUnexpectedEOF.Error()) {
							t.Fatalf("Open() = %v, want unexpected EOF", err)
						}
					}
				})
			}
		}
	}
}

func slideHeaderFixture(t *testing.T, version uint32) []byte {
	t.Helper()
	var header any
	switch version {
	case 1:
		header = CacheSlideInfo{Version: 1}
	case 2:
		header = CacheSlideInfo2{Version: 2, PageSize: 0x1000}
	case 3:
		header = CacheSlideInfo3{Version: 3, PageSize: 0x1000}
	case 4:
		header = CacheSlideInfo4{Version: 4, PageSize: 0x1000}
	case 5:
		header = CacheSlideInfo5{Version: 5, PageSize: 0x1000}
	default:
		t.Fatalf("unsupported slide version %d", version)
	}
	var data bytes.Buffer
	if err := binary.Write(&data, binary.LittleEndian, header); err != nil {
		t.Fatal(err)
	}
	return data.Bytes()
}
