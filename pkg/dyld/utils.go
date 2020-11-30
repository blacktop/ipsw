package dyld

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// Is64bit returns if dyld is 64bit or not
func (f *File) Is64bit() bool {
	return strings.Contains(string(f.Magic[:16]), "64")
}

// GetOffset returns the offset for a given virtual address
func (f *File) GetOffset(address uint64) (uint64, error) {
	for _, mapping := range f.Mappings {
		if mapping.Address <= address && address < mapping.Address+mapping.Size {
			return (address - mapping.Address) + mapping.FileOffset, nil
		}
	}
	return 0, fmt.Errorf("address not within any mappings address range")
}

// GetVMAddress returns the virtual address for a given offset
func (f *File) GetVMAddress(offset uint64) (uint64, error) {
	for _, mapping := range f.Mappings {
		if mapping.FileOffset <= offset && offset < mapping.FileOffset+mapping.Size {
			return (offset - mapping.FileOffset) + mapping.Address, nil
		}
	}
	return 0, fmt.Errorf("offset not within any mappings file offset range")
}

// ReadBytes returns bytes at a given offset
func (f *File) ReadBytes(offset int64, size uint64) ([]byte, error) {
	data := make([]byte, size)
	_, err := f.r.ReadAt(data, offset)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// ReadPointer returns bytes at a given offset
func (f *File) ReadPointer(offset uint64) (uint64, error) {
	u64 := make([]byte, 8)
	_, err := f.r.ReadAt(u64, int64(offset))
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(u64), nil
}

// ReadPointerAtAddress returns bytes at a given offset
func (f *File) ReadPointerAtAddress(addr uint64) (uint64, error) {
	offset, err := f.GetOffset(addr)
	if err != nil {
		return 0, err
	}
	return f.ReadPointer(offset)
}

func convertToVMAddr(addr uint64) uint64 {
	pointer := CacheSlidePointer3(addr)
	if pointer.Authenticated() {
		return 0x180000000 + pointer.OffsetFromSharedCacheBase()
	}
	return pointer.SignExtend51()
}
