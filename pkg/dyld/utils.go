package dyld

import (
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
func (f *File) ReadBytes(offset int64, size uint32) ([]byte, error) {
	data := make([]byte, size)
	_, err := f.r.ReadAt(data, offset)
	if err != nil {
		return nil, err
	}
	return data, nil
}
