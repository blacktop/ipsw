package dyld

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/blacktop/go-macho/types"
)

func output(show bool, fmtStr string, args ...any) {
	if show {
		fmt.Printf(fmtStr, args...)
	}
}

// Is64bit reports whether the cache uses 8-byte pointers; arm64_32 runs arm64
// instructions with 4-byte pointers
func (f *File) Is64bit() bool {
	magic := f.Headers[f.UUID].Magic.String()
	return strings.Contains(magic, "64") && !strings.Contains(magic, "arm64_32")
}

// IsArm64 returns if dyld is arm64 or not (meaning I can disassemble it)
func (f *File) IsArm64() bool {
	return strings.Contains(f.Headers[f.UUID].Magic.String(), "arm64")
}

// GetOffset returns the offset for a given virtual address and the cache's UUID that contains it
func (f *File) GetOffset(address uint64) (types.UUID, uint64, error) {
	for uuid, cacheMaps := range f.Mappings {
		for _, mapping := range cacheMaps {
			if mapping.Address <= address && address < mapping.Address+mapping.Size {
				return uuid, (address - mapping.Address) + mapping.FileOffset, nil
			}
		}
	}
	var badUUID types.UUID // will create a NULL uuid
	return badUUID, 0, fmt.Errorf("address %#x not within any mappings address range", address)
}

// GetOffsetForUUID returns the offset for a given virtual address for a given cache UUID
func (f *File) GetOffsetForUUID(uuid types.UUID, address uint64) (uint64, error) {
	for _, mapping := range f.Mappings[uuid] {
		if mapping.Address <= address && address < mapping.Address+mapping.Size {
			return (address - mapping.Address) + mapping.FileOffset, nil
		}
	}
	return 0, fmt.Errorf("address %#x not within any mappings address range", address)
}

// IsAddressInCache returns if the virtual address is in the cache's mappings
func (f *File) IsAddressInCache(uuid types.UUID, address uint64) bool {
	for _, mapping := range f.Mappings[uuid] {
		if mapping.Address <= address && address < mapping.Address+mapping.Size {
			return true
		}
	}
	return false
}

// GetVMAddress returns a map of uuids to virtual address for a given offset
func (f *File) GetVMAddress(offset uint64) (map[types.UUID]uint64, error) {
	uuid2addr := make(map[types.UUID]uint64)
	for uuid, cacheMaps := range f.Mappings {
		for _, mapping := range cacheMaps {
			if mapping.FileOffset <= offset && offset < mapping.FileOffset+mapping.Size {
				uuid2addr[uuid] = (offset - mapping.FileOffset) + mapping.Address
			}
		}
	}
	if len(uuid2addr) == 0 {
		return nil, fmt.Errorf("offset %#x not within any mappings file offset range", offset)
	}
	return uuid2addr, nil
}

// GetVMAddressForUUID returns the virtual address for a given offset for a given cache UUID
func (f *File) GetVMAddressForUUID(uuid types.UUID, offset uint64) (uint64, error) {
	for _, mapping := range f.MappingsWithSlideInfo[uuid] {
		if mapping.FileOffset <= offset && offset < mapping.FileOffset+mapping.Size {
			return (offset - mapping.FileOffset) + mapping.Address, nil
		}
	}
	return 0, fmt.Errorf("offset %#x not within any mappings file offset range", offset)
}

// GetCacheOffset converts an offset from the shared cache base to a file offset
func (f *File) GetCacheOffset(vmoffset uint64) (types.UUID, uint64, error) {
	uuid, address, err := f.GetCacheVMAddress(vmoffset)
	if err != nil {
		return types.UUID{}, 0, err
	}
	offset, err := f.GetOffsetForUUID(uuid, address)
	return uuid, offset, err
}

func (f *File) GetCacheOffsetFromAddress(addr uint64) (types.UUID, uint64, error) {
	vmstart := f.Headers[f.UUID].SharedRegionStart
	for idx, scinfo := range f.SubCacheInfo { // check the sub subcaches
		if idx < len(f.SubCacheInfo)-1 {
			if vmstart+scinfo.CacheVMOffset <= addr && addr < vmstart+f.SubCacheInfo[idx+1].CacheVMOffset {
				return scinfo.UUID, addr - (vmstart + scinfo.CacheVMOffset) + scinfo.CacheVMOffset, nil
			}
		} else {
			if vmstart+scinfo.CacheVMOffset <= addr {
				return scinfo.UUID, addr - (vmstart + scinfo.CacheVMOffset) + scinfo.CacheVMOffset, nil
			}
		}
	}
	// NOTE: via the dyld src comments; the .symbols subcache is unmmapped
	return types.UUID{}, 0, fmt.Errorf("address %#x not within any sub cache VM offset range", addr)
}

// GetCacheVMAddress resolves an offset from the shared cache base to its mapped address.
// Single-file caches have no subcache entries, so ownership is decided by the mappings:
// the primary cache first, then each subcache in header order. The .symbols file is
// never mapped and is not consulted.
func (f *File) GetCacheVMAddress(offset uint64) (types.UUID, uint64, error) {
	primary := f.Mappings[f.UUID]
	if len(primary) == 0 {
		return types.UUID{}, 0, fmt.Errorf("primary cache has no mappings")
	}
	base := primary[0].Address
	address := base + offset
	if address < base {
		return types.UUID{}, 0, fmt.Errorf("cache VM offset %#x overflows base address %#x", offset, base)
	}
	if mappingsContain(primary, address) {
		return f.UUID, address, nil
	}
	for _, sub := range f.SubCacheInfo {
		if mappingsContain(f.Mappings[sub.UUID], address) {
			return sub.UUID, address, nil
		}
	}
	return types.UUID{}, 0, fmt.Errorf("cache VM offset %#x (address %#x) not within any mapping", offset, address)
}

func mappingsContain(mappings cacheMappings, address uint64) bool {
	for _, mapping := range mappings {
		if mapping.Address <= address && address < mapping.Address+mapping.Size {
			return true
		}
	}
	return false
}

// GetMappingForOffsetForUUID returns the mapping containing a given file offset for a given cache UUID
func (f *File) GetMappingForOffsetForUUID(uuid types.UUID, offset uint64) (*CacheMapping, error) {
	for _, mapping := range f.Mappings[uuid] {
		if mapping.FileOffset <= offset && offset < mapping.FileOffset+mapping.Size {
			return mapping, nil
		}
	}
	return nil, fmt.Errorf("offset %#x not within any mappings file offset range", offset)
}

// GetMappingForVMAddress returns the mapping containing a given virtual address
func (f *File) GetMappingForVMAddress(address uint64) (types.UUID, *CacheMappingWithSlideInfo, error) {
	for uuid := range f.MappingsWithSlideInfo {
		for _, mapping := range f.MappingsWithSlideInfo[uuid] {
			if mapping.Address <= address && address < mapping.Address+mapping.Size {
				return uuid, mapping, nil
			}
		}
	}
	return types.UUID{}, nil, fmt.Errorf("address %#x not within any mapping's address range", address)
}

// ReadBytesForUUID returns bytes at a given offset for a given cache UUID
func (f *File) ReadBytesForUUID(uuid types.UUID, offset int64, size uint64) ([]byte, error) {
	data := make([]byte, size)
	if _, err := f.r[uuid].ReadAt(data, offset); err != nil {
		return nil, fmt.Errorf("failed to read bytes at offset %#x: %v", offset, err)
	}
	return data, nil
}

// ReadPointerForUUID returns pointer at a given offset for a given cache UUID
func (f *File) ReadPointerForUUID(uuid types.UUID, offset uint64) (uint64, error) {
	u64 := make([]byte, 8)
	if _, err := f.r[uuid].ReadAt(u64, int64(offset)); err != nil {
		return 0, fmt.Errorf("failed to read pointer at offset %#x: %v", offset, err)
	}
	return binary.LittleEndian.Uint64(u64), nil
}

// ReadPointerAtAddress returns pointer at a given virtual address
func (f *File) ReadPointerAtAddress(address uint64) (uint64, error) {
	uuid, offset, err := f.GetOffset(address)
	if err != nil {
		return 0, fmt.Errorf("failed to get offset for address %#x: %v", address, err)
	}
	return f.ReadPointerForUUID(uuid, offset)
}

func (f *File) GetSubCacheExtensionFromUUID(uuid types.UUID) (string, error) {
	for idx, sc := range f.SubCacheInfo {
		if sc.UUID == uuid {
			return subCacheSuffix(sc, idx), nil
		}
	}
	return "", fmt.Errorf("failed to find subcache extension for uuid %s", uuid.String())
}
