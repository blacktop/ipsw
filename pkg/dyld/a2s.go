package dyld

import (
	"bufio"
	"bytes"
	"cmp"
	"encoding/binary"
	"fmt"
	"io"
	"maps"
	"math"
	"os"
	"slices"
	"sync"

	"github.com/blacktop/go-macho/types"
)

var a2sMagic = [4]byte{'A', '2', 'S', 2}

const a2sEntrySize = 12  // addr(8) + strOffset(4)
const a2sHeaderSize = 12 // magic(4) + count(4) + strTabSize(4)

// A2STable is an address-to-symbol lookup table.
// During cache creation it uses a map for read-write access.
// When loaded from disk it uses mmap with binary search for O(log n) lookups
// touching only the pages needed.
//
// File format (v2):
//
//	[12] header: magic "A2S\x02" (4) + count (4) + strTabSize (4)
//	[12*N] entries sorted by addr: addr (8) + strOffset (4)
//	[strTabSize] string table: null-terminated strings packed contiguously
type A2STable struct {
	// mmap mode (loaded from file)
	data       []byte // mmap'd file data
	count      uint32 // number of entries
	strBase    int    // offset of string table in data
	strTabSize int    // size of string table in bytes

	// Additions and overrides; mutation requires exclusive access.
	m map[uint64]string

	changes uint64
	// Named stub maps belong to one File and one table revision. The mutex
	// serializes cache-building readers; table mutation still requires exclusive
	// access, just as it does for Get and Range.
	stubMu    sync.Mutex
	stubNames *namedStubCache
}

// NewA2STable creates a new table in build mode with the given capacity hint.
func NewA2STable(sizeHint int) *A2STable {
	return &A2STable{
		m: make(map[uint64]string, sizeHint),
	}
}

// Get looks up a symbol by address.
func (t *A2STable) Get(addr uint64) (string, bool) {
	if s, ok := t.m[addr]; ok {
		return s, true
	}
	return t.getMapped(addr)
}

// getMapped looks up an address in the immutable mapped entries.
func (t *A2STable) getMapped(addr uint64) (string, bool) {
	if t.data == nil {
		return "", false
	}
	// binary search on mmap'd entries
	lo, hi := 0, int(t.count)
	for lo < hi {
		mid := lo + (hi-lo)/2
		off := a2sHeaderSize + mid*a2sEntrySize
		entryAddr := binary.LittleEndian.Uint64(t.data[off:])
		if entryAddr < addr {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo < int(t.count) {
		off := a2sHeaderSize + lo*a2sEntrySize
		entryAddr := binary.LittleEndian.Uint64(t.data[off:])
		if entryAddr == addr {
			return t.stringAt(off)
		}
	}
	return "", false
}

// stringAt reads the NUL-terminated string for the entry at byte offset off.
func (t *A2STable) stringAt(off int) (string, bool) {
	strOff := int(binary.LittleEndian.Uint32(t.data[off+8:]))
	if strOff >= t.strTabSize {
		return "", false
	}
	start := t.strBase + strOff
	if start >= len(t.data) {
		return "", false
	}
	end := bytes.IndexByte(t.data[start:], 0)
	if end < 0 {
		return "", false
	}
	return string(t.data[start : start+end]), true
}

// GetValue returns the symbol for addr, or "" if not found.
func (t *A2STable) GetValue(addr uint64) string {
	s, _ := t.Get(addr)
	return s
}

// Set adds or overrides a symbol mapping, including on a loaded table.
func (t *A2STable) Set(addr uint64, name string) {
	if old, ok := t.Get(addr); ok && old == name {
		return
	}
	if t.m == nil {
		t.m = make(map[uint64]string)
	}
	t.m[addr] = name
	t.changed()
}

func (t *A2STable) changed() {
	t.changes++
	// Drop the cache as well as advancing the revision, including on wraparound.
	t.stubNames = nil
}

// Has returns true if addr exists in the table.
func (t *A2STable) Has(addr uint64) bool {
	_, ok := t.Get(addr)
	return ok
}

// Len returns the number of entries.
func (t *A2STable) Len() int {
	if t.data == nil {
		return len(t.m)
	}
	count := int(t.count)
	for addr := range t.m {
		if _, ok := t.getMapped(addr); !ok {
			count++
		}
	}
	return count
}

// Range iterates over the union in ascending address order, with additions
// overriding mapped entries. If fn returns false, iteration stops.
func (t *A2STable) Range(fn func(uint64, string) bool) {
	additions := slices.Sorted(maps.Keys(t.m))
	next := 0
	for i := 0; t.data != nil && i < int(t.count); i++ {
		off := a2sHeaderSize + i*a2sEntrySize
		addr := binary.LittleEndian.Uint64(t.data[off:])
		for next < len(additions) && additions[next] < addr {
			key := additions[next]
			if !fn(key, t.m[key]) {
				return
			}
			next++
		}
		if next < len(additions) && additions[next] == addr {
			if !fn(addr, t.m[addr]) {
				return
			}
			next++
		} else if sym, ok := t.stringAt(off); ok {
			if !fn(addr, sym) {
				return
			}
		}
	}
	for _, addr := range additions[next:] {
		if !fn(addr, t.m[addr]) {
			return
		}
	}
}

// Close releases mmap'd resources.
func (t *A2STable) Close() error {
	t.changed()
	t.m = nil
	if t.data != nil {
		err := a2sMunmap(t.data)
		t.data = nil
		t.count = 0
		return err
	}
	return nil
}

// Save writes the table to w in binary format v2: sorted entries + null-terminated string table.
func (t *A2STable) Save(w io.Writer) error {
	if t.m == nil && t.data == nil {
		return fmt.Errorf("a2s: nothing to save")
	}
	names := t.m
	if t.data != nil {
		names = make(map[uint64]string, t.Len())
		t.Range(func(addr uint64, name string) bool {
			names[addr] = name
			return true
		})
	}
	if uint64(len(names)) > math.MaxUint32 {
		return fmt.Errorf("a2s: too many entries")
	}

	type entry struct {
		addr   uint64
		strOff uint32
	}

	strTabSize, err := a2sStringTableSize(names, math.MaxUint32)
	if err != nil {
		return err
	}
	entries := make([]entry, 0, len(names))
	strBuf := make([]byte, 0, strTabSize)

	for addr := range names {
		entries = append(entries, entry{addr: addr})
	}
	slices.SortFunc(entries, func(a, b entry) int {
		return cmp.Compare(a.addr, b.addr)
	})

	// Pack names in address order for deterministic offsets.
	for i := range entries {
		entries[i].strOff = uint32(len(strBuf))
		strBuf = append(strBuf, names[entries[i].addr]...)
		strBuf = append(strBuf, 0) // null terminator
	}

	bw := bufio.NewWriterSize(w, 1<<20)

	// Header: magic(4) + count(4) + strTabSize(4)
	var hdr [a2sHeaderSize]byte
	copy(hdr[:4], a2sMagic[:])
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(len(entries)))
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(strBuf)))
	if _, err := bw.Write(hdr[:]); err != nil {
		return err
	}

	// Entries as raw bytes (12 bytes each: addr + strOffset)
	buf := make([]byte, len(entries)*a2sEntrySize)
	for i, e := range entries {
		off := i * a2sEntrySize
		binary.LittleEndian.PutUint64(buf[off:], e.addr)
		binary.LittleEndian.PutUint32(buf[off+8:], e.strOff)
	}
	if _, err := bw.Write(buf); err != nil {
		return err
	}

	// String table (null-terminated strings)
	if _, err := bw.Write(strBuf); err != nil {
		return err
	}

	return bw.Flush()
}

// a2sStringTableSize returns the size of the string table that holds every
// name NUL-terminated, or an error if it would exceed limit. The format
// stores string offsets and the table size as uint32.
func a2sStringTableSize(names map[uint64]string, limit uint64) (int, error) {
	var size uint64
	for _, name := range names {
		size += uint64(len(name)) + 1
		if size > limit || size > math.MaxInt {
			return 0, fmt.Errorf("a2s: string table exceeds %d bytes", limit)
		}
	}
	return int(size), nil
}

// Load memory-maps the cache file for O(log n) lookups with zero startup cost.
func (t *A2STable) Load(f *os.File, size int64) error {
	// Read and validate header
	var hdr [a2sHeaderSize]byte
	if _, err := f.ReadAt(hdr[:], 0); err != nil {
		return fmt.Errorf("a2s: failed to read header: %w", err)
	}
	var magic [4]byte
	copy(magic[:], hdr[:4])
	if magic != a2sMagic {
		return fmt.Errorf("a2s: invalid cache format; delete .a2s file and retry")
	}

	count := binary.LittleEndian.Uint32(hdr[4:8])
	strTabSize := binary.LittleEndian.Uint32(hdr[8:12])

	strBase := int64(a2sHeaderSize) + int64(count)*int64(a2sEntrySize)
	expectedSize := strBase + int64(strTabSize)
	if expectedSize > size {
		return fmt.Errorf("a2s: cache file truncated (need %d bytes, got %d); delete .a2s file and retry", expectedSize, size)
	}

	// mmap the entire file read-only (or read into memory on non-unix)
	data, err := a2sMmap(f, int(size))
	if err != nil {
		return fmt.Errorf("a2s: mmap failed: %w", err)
	}

	t.data = data
	t.count = count
	t.strBase = int(strBase)
	t.strTabSize = int(strTabSize)
	t.m = nil

	t.changed()
	return nil
}

// nlistSize is the serialized size of one local-symbol nlist entry: a 4-byte string
// index, type, section, 2-byte desc, then a 4- or 8-byte value
func nlistSize(is64bit bool) int {
	if is64bit {
		return 16
	}
	return 12
}

// parseNlist decodes exactly one little-endian nlist entry; the slice length selects the width
func parseNlist(b []byte) types.Nlist64 {
	var n types.Nlist64
	n.Name = binary.LittleEndian.Uint32(b)
	n.Type = types.NType(b[4])
	n.Sect = b[5]
	n.Desc = types.NDescType(binary.LittleEndian.Uint16(b[6:]))
	if len(b) == 16 {
		n.Value = binary.LittleEndian.Uint64(b[8:])
	} else {
		n.Value = uint64(binary.LittleEndian.Uint32(b[8:]))
	}
	return n
}

// readStringPool reads a NUL-terminated string from a string pool,
// retrying with a larger buffer if the initial chunk doesn't contain
// a NUL (handles long Swift-mangled names that exceed 512 bytes).
// Returns the grown buffer so callers in hot loops can reuse it.
func readStringPool(r io.ReaderAt, poolBase, poolSize, nameIdx int64, buf []byte) (string, []byte, error) {
	readOff := poolBase + nameIdx
	maxLen := poolSize - nameIdx
	if maxLen <= 0 {
		return "", buf, fmt.Errorf("string index %d out of range (pool size %d)", nameIdx, poolSize)
	}
	const initSize = 512
	if len(buf) < initSize {
		buf = make([]byte, initSize)
	}
	for chunkSize := int64(len(buf)); ; chunkSize *= 4 {
		if chunkSize > maxLen {
			chunkSize = maxLen
		}
		if int64(len(buf)) < chunkSize {
			buf = make([]byte, chunkSize)
		}
		nr, err := r.ReadAt(buf[:chunkSize], readOff)
		if err != nil && nr == 0 {
			return "", buf, fmt.Errorf("failed to read string at offset %#x: %w", readOff, err)
		}
		if nullPos := bytes.IndexByte(buf[:nr], 0); nullPos >= 0 {
			return string(buf[:nullPos]), buf, nil
		}
		if chunkSize >= maxLen {
			return string(buf[:nr]), buf, nil
		}
	}
}
