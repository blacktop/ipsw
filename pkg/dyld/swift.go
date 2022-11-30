package dyld

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho/types"
)

type SwiftOptimizationHeader struct {
	Version                                    uint32
	Padding                                    uint32
	TypeConformanceHashTableCacheOffset        uint64
	MetadataConformanceHashTableCacheOffset    uint64
	ForeignTypeConformanceHashTableCacheOffset uint64
}

type SwiftProtocolConformance struct {
	Key      SwiftProtocolConformanceLocationKey
	Location SwiftProtocolConformanceLocation
}

func (p SwiftProtocolConformance) String() string {
	return fmt.Sprintf("%s, %s", p.Key, p.Location)
}

type SwiftProtocolConformanceLocationKey struct {
	TypeDescriptorCacheOffset uint64
	ProtocolCacheOffset       uint64
}

func (k SwiftProtocolConformanceLocationKey) String() string {
	return fmt.Sprintf("type_descriptor: %#x, protocol: %#x", k.TypeDescriptorCacheOffset, k.ProtocolCacheOffset)
}

type SwiftProtocolConformanceLocation uint64

func (l SwiftProtocolConformanceLocation) Raw() uint64 {
	return uint64(l)
}
func (l SwiftProtocolConformanceLocation) NextIsDuplicate() bool {
	return types.ExtractBits(uint64(l), 0, 1) != 0
}

// Offset from the shared cache base to the conformance object
func (l SwiftProtocolConformanceLocation) ProtocolConformanceCacheOffset() uint64 {
	return types.ExtractBits(uint64(l), 1, 47)
}

// Index in to the HeaderInfoRW dylibs for the dylib containing this conformance
func (l SwiftProtocolConformanceLocation) DylibObjCIndex() uint64 {
	return types.ExtractBits(uint64(l), 48, 16)
}

func (l SwiftProtocolConformanceLocation) String() string {
	var isdup string
	if l.NextIsDuplicate() {
		isdup = " (next is duplicate)"
	}
	return fmt.Sprintf("proto_conformance: %#x, dylib_objc_index: %d%s",
		l.ProtocolConformanceCacheOffset(),
		l.DylibObjCIndex(),
		isdup)
}

type SwiftMetadataProtocolConformance SwiftProtocolConformance

type SwiftForeignTypeProtocolConformance struct {
	Key      SwiftForeignTypeProtocolConformanceLocationKey
	Location SwiftProtocolConformanceLocation
}

func (p SwiftForeignTypeProtocolConformance) String() string {
	return fmt.Sprintf("%s, %s", p.Key, p.Location)
}

type rawForeignDescriptor uint64

func (fd rawForeignDescriptor) ForeignDescriptorNameCacheOffset() uint64 {
	return types.ExtractBits(uint64(fd), 0, 48)
}
func (fd rawForeignDescriptor) ForeignDescriptorNameLength() uint16 {
	return uint16(types.ExtractBits(uint64(fd), 48, 16))
}

type SwiftForeignTypeProtocolConformanceLocationKey struct {
	RawForeignDescriptor rawForeignDescriptor
	ProtocolCacheOffset  uint64
}

func (k SwiftForeignTypeProtocolConformanceLocationKey) String() string {
	return fmt.Sprintf("name_cache: %#x, name_length: %d, protocol: %#x",
		k.RawForeignDescriptor.ForeignDescriptorNameCacheOffset(),
		k.RawForeignDescriptor.ForeignDescriptorNameLength(),
		k.ProtocolCacheOffset)
}

func (f *File) GetAllSwiftTypes(print bool) (map[string]uint64, error) {

	shash, err := f.getSwiftTypeHashTable()
	if err != nil {
		return nil, fmt.Errorf("failed read type conformance SwiftHashTable: %v", err)
	}

	if print {
		f.dumpSwiftOffsets(shash)
	}

	return f.offsetsToMap(shash.Offsets, int64(shash.CacheOffset), f.UUID), nil // FIXME: handle multiple UUIDs
}

func (f *File) GetAllSwiftMetadatas(print bool) (map[string]uint64, error) {

	shash, err := f.getSwiftMetadataTable()
	if err != nil {
		return nil, fmt.Errorf("failed read metadata conformance SwiftHashTable: %v", err)
	}

	if print {
		f.dumpSwiftOffsets(shash)
	}

	return f.offsetsToMap(shash.Offsets, int64(shash.CacheOffset), f.UUID), nil // FIXME: handle multiple UUIDs
}

func (f *File) GetAllSwiftForeignTypes(print bool) (map[string]uint64, error) {

	shash, err := f.getSwiftForeignTypeHashTable()
	if err != nil {
		return nil, fmt.Errorf("failed read foreign type conformance SwiftHashTable: %v", err)
	}

	if print {
		f.dumpSwiftOffsets(shash)
	}

	return f.offsetsToMap(shash.Offsets, int64(shash.CacheOffset), f.UUID), nil // FIXME: handle multiple UUIDs
}

type swiftHashTable struct {
	Capacity       uint32
	Occupied       uint32
	Shift          uint32
	Mask           uint32
	SentinelTarget uint32
	RoundedTabSize uint32
	Salt           uint64
	Scramble       [256]uint32
}

type swiftHashTableType uint8

const (
	TypeConformance = iota
	MetadataConformance
	ForeignTypeConformance
)

type SwiftHashTable struct {
	CacheOffset uint64
	UUID        types.UUID
	Type        swiftHashTableType
	swiftHashTable
	Tab        []byte  /* tab[mask+1] (always power-of-2). Rounded up to roundedTabSize */
	CheckBytes []byte  /* check byte for each string */
	Offsets    []int32 /* offsets from &capacity to cstrings */
}

func (s *SwiftHashTable) Read(r *io.SectionReader) error {
	r.Seek(int64(s.CacheOffset), io.SeekStart)

	if err := binary.Read(r, binary.LittleEndian, &s.swiftHashTable); err != nil {
		return fmt.Errorf("failed to read %T: %v", s.swiftHashTable, err)
	}

	s.Tab = make([]byte, s.Mask+1)
	if err := binary.Read(r, binary.LittleEndian, &s.Tab); err != nil {
		return fmt.Errorf("failed to read %T: %v", s.Tab, err)
	}

	s.CheckBytes = make([]byte, s.Capacity)
	if err := binary.Read(r, binary.LittleEndian, &s.CheckBytes); err != nil {
		return fmt.Errorf("failed to read %T: %v", s.CheckBytes, err)
	}

	s.Offsets = make([]int32, s.Capacity)
	if err := binary.Read(r, binary.LittleEndian, &s.Offsets); err != nil {
		return fmt.Errorf("failed to read %T: %v", s.Offsets, err)
	}

	return nil
}

func (f *File) getSwiftTypeHashTable() (*SwiftHashTable, error) {
	if f.IsDyld4 && f.Headers[f.UUID].SwiftOptsOffset > 0 {
		uuid, off, err := f.GetCacheOffset(f.Headers[f.UUID].SwiftOptsOffset)
		if err != nil {
			return nil, err
		}

		sr := io.NewSectionReader(f.r[uuid], 0, 1<<63-1)
		sr.Seek(int64(off), io.SeekStart)

		var h SwiftOptimizationHeader
		if err := binary.Read(sr, binary.LittleEndian, &h); err != nil {
			return nil, fmt.Errorf("failed to read %T: %v", h, err)
		}

		if h.Version != 1 {
			return nil, fmt.Errorf("unsupported Swift optimization version: %d", h.Version)
		}

		uuid, off, err = f.GetCacheOffset(h.TypeConformanceHashTableCacheOffset)
		if err != nil {
			return nil, err
		}

		shash := SwiftHashTable{CacheOffset: off, UUID: uuid, Type: TypeConformance}

		if err := shash.Read(io.NewSectionReader(f.r[uuid], 0, 1<<63-1)); err != nil {
			return nil, fmt.Errorf("failed to read %T: %v", shash, err)
		}

		return &shash, nil
	}

	return nil, fmt.Errorf("no swift optimization header")
}

func (f *File) getSwiftMetadataTable() (*SwiftHashTable, error) {
	if f.IsDyld4 && f.Headers[f.UUID].SwiftOptsOffset > 0 {
		uuid, off, err := f.GetCacheOffset(f.Headers[f.UUID].SwiftOptsOffset)
		if err != nil {
			return nil, err
		}

		sr := io.NewSectionReader(f.r[uuid], 0, 1<<63-1)
		sr.Seek(int64(off), io.SeekStart)

		var h SwiftOptimizationHeader
		if err := binary.Read(sr, binary.LittleEndian, &h); err != nil {
			return nil, fmt.Errorf("failed to read %T: %v", h, err)
		}

		if h.Version != 1 {
			return nil, fmt.Errorf("unsupported Swift optimization version: %d", h.Version)
		}

		uuid, off, err = f.GetCacheOffset(h.MetadataConformanceHashTableCacheOffset)
		if err != nil {
			return nil, err
		}

		shash := SwiftHashTable{CacheOffset: off, UUID: uuid, Type: MetadataConformance}

		if err := shash.Read(io.NewSectionReader(f.r[uuid], 0, 1<<63-1)); err != nil {
			return nil, fmt.Errorf("failed to read %T: %v", shash, err)
		}

		return &shash, nil
	}

	return nil, fmt.Errorf("no swift optimization header")
}

func (f *File) getSwiftForeignTypeHashTable() (*SwiftHashTable, error) {
	if f.IsDyld4 && f.Headers[f.UUID].SwiftOptsOffset > 0 {
		uuid, off, err := f.GetCacheOffset(f.Headers[f.UUID].SwiftOptsOffset)
		if err != nil {
			return nil, err
		}

		sr := io.NewSectionReader(f.r[uuid], 0, 1<<63-1)
		sr.Seek(int64(off), io.SeekStart)

		var h SwiftOptimizationHeader
		if err := binary.Read(sr, binary.LittleEndian, &h); err != nil {
			return nil, fmt.Errorf("failed to read %T: %v", h, err)
		}

		if h.Version != 1 {
			return nil, fmt.Errorf("unsupported Swift optimization version: %d", h.Version)
		}

		uuid, off, err = f.GetCacheOffset(h.ForeignTypeConformanceHashTableCacheOffset)
		if err != nil {
			return nil, err
		}

		shash := SwiftHashTable{CacheOffset: off, UUID: uuid, Type: ForeignTypeConformance}

		if err := shash.Read(io.NewSectionReader(f.r[uuid], 0, 1<<63-1)); err != nil {
			return nil, fmt.Errorf("failed to read %T: %v", shash, err)
		}

		return &shash, nil
	}

	return nil, fmt.Errorf("no swift optimization header")
}

func (f *File) dumpSwiftOffsets(h *SwiftHashTable) {
	var imgName string
	sr := io.NewSectionReader(f.r[h.UUID], 0, 1<<63-1)
	for _, ptr := range h.Offsets {
		if ptr != int32(h.SentinelTarget) {
			var protocolCacheOffset uint64
			var protocolConformanceCacheOffset uint64

			sr.Seek(int64(int32(h.CacheOffset)+ptr), io.SeekStart)

			switch h.Type {
			case TypeConformance, MetadataConformance:
				var pconf SwiftProtocolConformance
				if err := binary.Read(sr, binary.LittleEndian, &pconf); err != nil {
					log.Errorf("failed to read %T: %v\n", pconf, err)
					continue
				}

				fmt.Printf("%s: %s\n", symDarkAddrColor("%#x", int64(int32(h.CacheOffset)+ptr)), symImageColor(pconf.String()))

				protocolCacheOffset = pconf.Key.ProtocolCacheOffset
				protocolConformanceCacheOffset = pconf.Location.ProtocolConformanceCacheOffset()

				_, addr, err := f.GetCacheVMAddress(pconf.Key.TypeDescriptorCacheOffset)
				if err != nil {
					log.Errorf("failed to get vm address: %v", err)
					continue
				}
				typeName, ok := f.AddressToSymbol[addr]
				if !ok {
					typeName = "n/a"
				}
				i, err := f.GetImageContainingVMAddr(addr)
				if err == nil {
					imgName = filepath.Base(i.Name)
				} else {
					imgName = ""
				}
				sType := "T"
				if h.Type == MetadataConformance {
					sType = "M"
				}

				fmt.Printf("    %s: %s %s\t%s\n", symAddrColor("%#x", addr), symTypeColor(sType), symNameColor(strings.Trim(typeName, "\x00")), symImageColor(imgName))
			case ForeignTypeConformance:
				var pconf SwiftForeignTypeProtocolConformance
				if err := binary.Read(sr, binary.LittleEndian, &pconf); err != nil {
					log.Errorf("failed to read %T: %v\n", pconf, err)
					continue
				}

				fmt.Printf("%s: %s\n", symDarkAddrColor("%#x", int64(int32(h.CacheOffset)+ptr)), symImageColor(pconf.String()))

				protocolCacheOffset = pconf.Key.ProtocolCacheOffset
				protocolConformanceCacheOffset = pconf.Location.ProtocolConformanceCacheOffset()

				_, addr, err := f.GetCacheVMAddress(pconf.Key.RawForeignDescriptor.ForeignDescriptorNameCacheOffset())
				if err != nil {
					log.Errorf("failed to get vm address: %v", err)
					continue
				}
				uuid, off, err := f.GetCacheOffset(pconf.Key.RawForeignDescriptor.ForeignDescriptorNameCacheOffset())
				if err != nil {
					log.Errorf("failed to get vm address: %v", err)
					continue
				}
				dat, err := f.ReadBytesForUUID(uuid, int64(off), uint64(pconf.Key.RawForeignDescriptor.ForeignDescriptorNameLength()))
				if err != nil {
					log.Errorf("failed to read bytes: %v", err)
				}
				var names []string
				words := bytes.Split(dat, []byte{0x00})
				for _, w := range words {
					names = append(names, string(w))
				}

				fmt.Printf("    %s: %s %s\n", symAddrColor("%#x", addr), symTypeColor("T"), symNameColor(strings.Join(names, " ")))
			}

			_, addr, err := f.GetCacheVMAddress(protocolCacheOffset)
			if err != nil {
				log.Errorf("failed to get vm address: %v", err)
				continue
			}
			protoName, ok := f.AddressToSymbol[addr]
			if !ok {
				protoName = "n/a"
			}
			i, err := f.GetImageContainingVMAddr(addr)
			if err == nil {
				imgName = filepath.Base(i.Name)
			} else {
				imgName = ""
			}

			fmt.Printf("    %s: %s %s\t%s\n", symAddrColor("%#x", addr), symTypeColor("P"), symNameColor(strings.Trim(protoName, "\x00")), symImageColor(imgName))

			_, addr, err = f.GetCacheVMAddress(protocolConformanceCacheOffset)
			if err != nil {
				log.Errorf("failed to get vm address: %v", err)
				continue
			}
			protoConfName, ok := f.AddressToSymbol[addr]
			if !ok {
				protoConfName = "n/a"
			}
			i, err = f.GetImageContainingVMAddr(addr)
			if err == nil {
				imgName = filepath.Base(i.Name)
			} else {
				imgName = ""
			}

			fmt.Printf("    %s: %s %s\t%s\n", symAddrColor("%#x", addr), symTypeColor("C"), symNameColor(strings.Trim(protoConfName, "\x00")), symImageColor(imgName))
		}

	}
}
