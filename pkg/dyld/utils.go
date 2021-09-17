package dyld

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/blacktop/go-macho/types"
)

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

// GetVMAddressForUUID returns the virtual address for a given offset for a given cache UUID
func (f *File) GetVMAddressForUUID(uuid types.UUID, offset uint64) (uint64, error) {
	for _, mapping := range f.Mappings[uuid] {
		if mapping.FileOffset <= offset && offset < mapping.FileOffset+mapping.Size {
			return (offset - mapping.FileOffset) + mapping.Address, nil
		}
	}
	return 0, fmt.Errorf("offset %#x not within any mappings file offset range", offset)
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
func (f *File) GetMappingForVMAddress(address uint64) (*CacheMapping, error) {
	for _, cacheMaps := range f.Mappings {
		for _, mapping := range cacheMaps {
			if mapping.Address <= address && address < mapping.Address+mapping.Size {
				return mapping, nil
			}
		}
	}
	return nil, fmt.Errorf("address %#x not within any mapping's address range", address)
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
