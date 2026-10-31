package dyld

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unsafe"
)

func cacheCPUFieldsEnd() uint32 {
	return uint32(unsafe.Offsetof(CacheHeader{}.CacheCPUReserved) + unsafe.Sizeof(CacheHeader{}.CacheCPUReserved))
}

func TestCacheHeaderHasSwiftOptsFields(t *testing.T) {
	end := uint32(unsafe.Offsetof(CacheHeader{}.SwiftOptsSize) + unsafe.Sizeof(CacheHeader{}.SwiftOptsSize))
	for _, tc := range []struct {
		offset uint32
		want   bool
	}{{0x140, false}, {end - 1, false}, {end, true}} {
		if got := (CacheHeader{MappingOffset: tc.offset}).HasSwiftOptsFields(); got != tc.want {
			t.Errorf("HasSwiftOptsFields(%#x) = %t, want %t", tc.offset, got, tc.want)
		}
	}
}

func TestCacheHeaderCacheCPULayout(t *testing.T) {
	prewarmingEnd := unsafe.Offsetof(CacheHeader{}.PrewarmingDataSize) + unsafe.Sizeof(CacheHeader{}.PrewarmingDataSize)
	if got := unsafe.Offsetof(CacheHeader{}.CacheCPUType); got != prewarmingEnd {
		t.Errorf("CacheCPUType offset = %#x, want %#x (immediately after PrewarmingDataSize)", got, prewarmingEnd)
	}
	if got := unsafe.Offsetof(CacheHeader{}.CacheCPUSubtype); got != prewarmingEnd+4 {
		t.Errorf("CacheCPUSubtype offset = %#x, want %#x", got, prewarmingEnd+4)
	}
	if got := unsafe.Offsetof(CacheHeader{}.CacheCPUReserved); got != prewarmingEnd+8 {
		t.Errorf("CacheCPUReserved offset = %#x, want %#x", got, prewarmingEnd+8)
	}
}

func TestCacheHeaderCacheCPUDecode(t *testing.T) {
	tests := []struct {
		name         string
		raw          [16]byte
		wantType     uint32
		wantSubtype  uint32
		wantReserved uint64
		wantArch     string
	}{
		{
			name:         "arm64e",
			raw:          [16]byte{0x0c, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 0, 0},
			wantType:     0x0100000c,
			wantSubtype:  0x80000002,
			wantReserved: 0,
			wantArch:     "AARCH64, ARM64e caps: USR00",
		},
		{
			name:         "x86_64",
			raw:          [16]byte{0x07, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0},
			wantType:     0x01000007,
			wantSubtype:  0x00000003,
			wantReserved: 0,
			wantArch:     "Amd64, x86_64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, binary.Size(CacheHeader{}))
			binary.LittleEndian.PutUint32(buf[unsafe.Offsetof(CacheHeader{}.MappingOffset):], cacheCPUFieldsEnd())
			copy(buf[unsafe.Offsetof(CacheHeader{}.CacheCPUType):], tt.raw[:])

			var hdr CacheHeader
			if err := binary.Read(bytes.NewReader(buf), binary.LittleEndian, &hdr); err != nil {
				t.Fatalf("binary.Read() error = %v", err)
			}

			if !hdr.HasCacheCPUFields() {
				t.Fatalf("HasCacheCPUFields() = false, want true (MappingOffset = %#x)", hdr.MappingOffset)
			}
			if got := uint32(hdr.CacheCPUType); got != tt.wantType {
				t.Errorf("CacheCPUType = %#08x, want %#08x", got, tt.wantType)
			}
			if got := uint32(hdr.CacheCPUSubtype); got != tt.wantSubtype {
				t.Errorf("CacheCPUSubtype = %#08x, want %#08x", got, tt.wantSubtype)
			}
			if hdr.CacheCPUReserved != tt.wantReserved {
				t.Errorf("CacheCPUReserved = %#x, want %#x", hdr.CacheCPUReserved, tt.wantReserved)
			}
			if got := hdr.CacheCPUString(); got != tt.wantArch {
				t.Errorf("CacheCPUString() = %q, want %q", got, tt.wantArch)
			}
		})
	}
}

func TestCacheHeaderHasCacheCPUFields(t *testing.T) {
	oldHeaderEnd := uint32(unsafe.Offsetof(CacheHeader{}.CacheCPUType))

	tests := []struct {
		name          string
		mappingOffset uint32
		want          bool
	}{
		{"old header ending at prewarmingDataSize", oldHeaderEnd, false},
		{"one byte short of the extension end", cacheCPUFieldsEnd() - 1, false},
		{"header includes cache cpu fields", cacheCPUFieldsEnd(), true},
		{"future header larger than extension", cacheCPUFieldsEnd() + 0x20, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hdr := CacheHeader{MappingOffset: tt.mappingOffset}
			if got := hdr.HasCacheCPUFields(); got != tt.want {
				t.Errorf("HasCacheCPUFields() = %t, want %t (MappingOffset = %#x)", got, tt.want, tt.mappingOffset)
			}
		})
	}
}

func TestCacheHeaderHasAppendedFields(t *testing.T) {
	imagesTextEnd := uint32(unsafe.Offsetof(CacheHeader{}.ImagesTextCount) + unsafe.Sizeof(CacheHeader{}.ImagesTextCount))
	rosettaEnd := uint32(unsafe.Offsetof(CacheHeader{}.RosettaReadWriteSize) + unsafe.Sizeof(CacheHeader{}.RosettaReadWriteSize))
	objcOptsEnd := uint32(unsafe.Offsetof(CacheHeader{}.ObjcOptsSize) + unsafe.Sizeof(CacheHeader{}.ObjcOptsSize))
	dynamicDataEnd := uint32(unsafe.Offsetof(CacheHeader{}.DynamicDataMaxSize) + unsafe.Sizeof(CacheHeader{}.DynamicDataMaxSize))

	tests := []struct {
		name           string
		mappingOffset  uint32
		wantImagesText bool
		wantRosetta    bool
		wantObjcOpts   bool
		wantDynamic    bool
	}{
		{"iOS 8 header (0x70)", 0x70, false, false, false, false},
		{"one byte short of the images text fields end", imagesTextEnd - 1, false, false, false, false},
		{"header includes images text fields", imagesTextEnd, true, false, false, false},
		{"macOS 11 header (0x140)", 0x140, true, false, false, false},
		{"one byte short of the rosetta fields end", rosettaEnd - 1, true, false, false, false},
		{"header includes rosetta fields", rosettaEnd, true, true, false, false},
		{"macOS 12 header (0x1c8)", 0x1c8, true, true, false, false},
		{"header includes objcOpts fields", objcOptsEnd, true, true, true, false},
		{"one byte short of the dynamic data fields end", dynamicDataEnd - 1, true, true, true, false},
		{"macOS 13 header (0x200)", 0x200, true, true, true, true},
		{"full header", uint32(binary.Size(CacheHeader{})), true, true, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hdr := CacheHeader{MappingOffset: tt.mappingOffset}
			if got := hdr.HasImagesTextFields(); got != tt.wantImagesText {
				t.Errorf("HasImagesTextFields() = %t, want %t (MappingOffset = %#x)", got, tt.wantImagesText, tt.mappingOffset)
			}
			if got := hdr.HasRosettaFields(); got != tt.wantRosetta {
				t.Errorf("HasRosettaFields() = %t, want %t (MappingOffset = %#x)", got, tt.wantRosetta, tt.mappingOffset)
			}
			if got := hdr.HasObjcOptsFields(); got != tt.wantObjcOpts {
				t.Errorf("HasObjcOptsFields() = %t, want %t (MappingOffset = %#x)", got, tt.wantObjcOpts, tt.mappingOffset)
			}
			if got := hdr.HasDynamicDataFields(); got != tt.wantDynamic {
				t.Errorf("HasDynamicDataFields() = %t, want %t (MappingOffset = %#x)", got, tt.wantDynamic, tt.mappingOffset)
			}
		})
	}
}
