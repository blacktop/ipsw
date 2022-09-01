package dyld

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
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
	return fmt.Sprintf("next_is_duplicate: %t, proto_conformance_offset: %#x, dylib_objc_index: %d",
		l.NextIsDuplicate(),
		l.ProtocolConformanceCacheOffset(),
		l.DylibObjCIndex())
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

type SwiftHashTable struct {
	CacheOffset uint64
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
		r := io.NewSectionReader(f.r[f.UUID], int64(f.Headers[f.UUID].SwiftOptsOffset), int64(f.Headers[f.UUID].SwiftOptsSize))

		var h SwiftOptimizationHeader
		if err := binary.Read(r, binary.LittleEndian, &h); err != nil {
			return nil, fmt.Errorf("failed to read %T: %v", h, err)
		}

		shash := SwiftHashTable{CacheOffset: h.TypeConformanceHashTableCacheOffset}

		if err := shash.Read(io.NewSectionReader(f.r[f.UUID], 0, 1<<63-1)); err != nil {
			return nil, fmt.Errorf("failed to read %T: %v", shash, err)
		}

		return &shash, nil
	}

	return nil, fmt.Errorf("no swift optimization header")
}

func (f *File) getSwiftMetadataTable() (*SwiftHashTable, error) {
	if f.IsDyld4 && f.Headers[f.UUID].SwiftOptsOffset > 0 {
		r := io.NewSectionReader(f.r[f.UUID], int64(f.Headers[f.UUID].SwiftOptsOffset), int64(f.Headers[f.UUID].SwiftOptsSize))

		var h SwiftOptimizationHeader
		if err := binary.Read(r, binary.LittleEndian, &h); err != nil {
			return nil, fmt.Errorf("failed to read %T: %v", h, err)
		}

		shash := SwiftHashTable{CacheOffset: h.TypeConformanceHashTableCacheOffset}

		if err := shash.Read(io.NewSectionReader(f.r[f.UUID], 0, 1<<63-1)); err != nil {
			return nil, fmt.Errorf("failed to read %T: %v", shash, err)
		}

		return &shash, nil
	}

	return nil, fmt.Errorf("no swift optimization header")
}

func (f *File) getSwiftForeignTypeHashTable() (*SwiftHashTable, error) {
	if f.IsDyld4 && f.Headers[f.UUID].SwiftOptsOffset > 0 {
		r := io.NewSectionReader(f.r[f.UUID], int64(f.Headers[f.UUID].SwiftOptsOffset), int64(f.Headers[f.UUID].SwiftOptsSize))

		var h SwiftOptimizationHeader
		if err := binary.Read(r, binary.LittleEndian, &h); err != nil {
			return nil, fmt.Errorf("failed to read %T: %v", h, err)
		}

		shash := SwiftHashTable{CacheOffset: h.TypeConformanceHashTableCacheOffset}

		if err := shash.Read(io.NewSectionReader(f.r[f.UUID], 0, 1<<63-1)); err != nil {
			return nil, fmt.Errorf("failed to read %T: %v", shash, err)
		}

		return &shash, nil
	}

	return nil, fmt.Errorf("no swift optimization header")
}

func (f *File) dumpSwiftOffsets(h *SwiftHashTable) {
	// sort.Slice(h.Offsets, func(i, j int) bool { return h.Offsets[i] < h.Offsets[j] })
	sr := io.NewSectionReader(f.r[f.UUID], 0, 1<<63-1)
	for _, ptr := range h.Offsets {
		if ptr != int32(h.SentinelTarget) {
			sr.Seek(int64(int32(h.CacheOffset)+ptr), io.SeekStart)
			var pconf SwiftProtocolConformance
			if err := binary.Read(sr, binary.LittleEndian, &pconf); err != nil {
				fmt.Printf("failed to read %T: %v\n", pconf, err)
				continue
			}
			fmt.Println(pconf)
			addr := f.Headers[f.UUID].SharedRegionStart + pconf.Key.ProtocolCacheOffset
			uuid, off, err := f.GetOffset(addr)
			if err != nil {
				log.Errorf("failed to get offset: %v", err)
			}
			pr := io.NewSectionReader(f.r[uuid], 0, 1<<63-1)
			pr.Seek(int64(off), io.SeekStart)
			s, err := bufio.NewReader(pr).ReadString('\x00')
			if err != nil {
				log.Errorf("failed to read selector name at %#x: %v", h.CacheOffset+pconf.Key.TypeDescriptorCacheOffset, err)
			}
			fmt.Printf("    0x%x: %s\n", addr, strings.Trim(s, "\x00"))
		}

	}
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
