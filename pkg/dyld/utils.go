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

// Is64bit returns if dyld is 64bit or not
func (f *File) Is64bit() bool {
	return strings.Contains(f.Headers[f.UUID].Magic.String(), "64")
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

func (f *File) GetCacheOffset(vmoffset uint64) (types.UUID, uint64, error) {
	if vmoffset < f.SubCacheInfo[0].CacheVMOffset {
		return f.UUID, vmoffset, nil // vm offset in primary subcache
	}
	for idx, scinfo := range f.SubCacheInfo { // check the sub subcaches
		if idx < len(f.SubCacheInfo)-1 {
			if scinfo.CacheVMOffset <= vmoffset && vmoffset < f.SubCacheInfo[idx+1].CacheVMOffset {
				return scinfo.UUID, vmoffset - scinfo.CacheVMOffset, nil
			}
		} else {
			if scinfo.CacheVMOffset <= vmoffset {
				return scinfo.UUID, vmoffset - scinfo.CacheVMOffset, nil
			}
		}
	}
	// NOTE: via the dyld src comments; the .symbols subcache is unmmapped
	return types.UUID{}, 0, fmt.Errorf("offset %#x not within any sub cache VM offset range", vmoffset)
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

func (f *File) GetCacheVMAddress(offset uint64) (types.UUID, uint64, error) {
	if offset < f.SubCacheInfo[0].CacheVMOffset {
		return f.UUID, f.MappingsWithSlideInfo[f.UUID][0].Address + offset, nil // vm addr in primary subcache
	}
	for idx, scinfo := range f.SubCacheInfo { // check the sub subcaches
		if idx < len(f.SubCacheInfo)-1 {
			if scinfo.CacheVMOffset <= offset && offset < f.SubCacheInfo[idx+1].CacheVMOffset {
				return scinfo.UUID, f.MappingsWithSlideInfo[scinfo.UUID][0].Address + (offset - scinfo.CacheVMOffset), nil
			}
		} else {
			if scinfo.CacheVMOffset <= offset {
				return scinfo.UUID, f.MappingsWithSlideInfo[scinfo.UUID][0].Address + (offset - scinfo.CacheVMOffset), nil
			}
		}
	}
	// NOTE: via the dyld src comments; the .symbols subcache is unmmapped
	return types.UUID{}, 0, fmt.Errorf("offset %#x not within any sub cache VM offset range", offset)
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
			if len(sc.Extention) == 0 {
				return fmt.Sprintf(".%d", idx), nil
			}
			return sc.Extention, nil
		}
	}
	return "", fmt.Errorf("failed to find subcache extension for uuid %s", uuid.String())
}
