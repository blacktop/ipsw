package dyld

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"
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

	// build mode; cache construction mutates this on one goroutine before Save/Load.
	m map[uint64]string
}

// NewA2STable creates a new table in build mode with the given capacity hint.
func NewA2STable(sizeHint int) *A2STable {
	return &A2STable{
		m: make(map[uint64]string, sizeHint),
	}
}

// Get looks up a symbol by address.
func (t *A2STable) Get(addr uint64) (string, bool) {
	if t.m != nil {
		s, ok := t.m[addr]
		return s, ok
	}
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

// Set adds or updates a symbol mapping. Only valid in build mode.
func (t *A2STable) Set(addr uint64, name string) {
	if t.m == nil {
		t.m = make(map[uint64]string)
	}
	t.m[addr] = name
}

// Has returns true if addr exists in the table.
func (t *A2STable) Has(addr uint64) bool {
	_, ok := t.Get(addr)
	return ok
}

// Len returns the number of entries.
func (t *A2STable) Len() int {
	if t.m != nil {
		return len(t.m)
	}
	return int(t.count)
}

// Range iterates over all entries. If fn returns false, iteration stops.
func (t *A2STable) Range(fn func(uint64, string) bool) {
	if t.m != nil {
		for addr, sym := range t.m {
			if !fn(addr, sym) {
				return
			}
		}
		return
	}
	if t.data == nil {
		return
	}
	for i := 0; i < int(t.count); i++ {
		off := a2sHeaderSize + i*a2sEntrySize
		addr := binary.LittleEndian.Uint64(t.data[off:])
		sym, ok := t.stringAt(off)
		if !ok {
			continue
		}
		if !fn(addr, sym) {
			return
		}
	}
}

// Close releases mmap'd resources.
func (t *A2STable) Close() error {
	if t.data != nil {
		err := a2sMunmap(t.data)
		t.data = nil
		return err
	}
	return nil
}

// Save writes the table to w in binary format v2: sorted entries + null-terminated string table.
func (t *A2STable) Save(w io.Writer) error {
	if t.m == nil {
		return fmt.Errorf("a2s: nothing to save")
	}

	type entry struct {
		addr   uint64
		strOff uint32
	}

	entries := make([]entry, 0, len(t.m))
	var strBuf []byte

	for addr, name := range t.m {
		entries = append(entries, entry{
			addr:   addr,
			strOff: uint32(len(strBuf)),
		})
		strBuf = append(strBuf, name...)
		strBuf = append(strBuf, 0) // null terminator
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].addr < entries[j].addr
	})

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

	return nil
}

// nlist64Size is the byte size of a serialized Nlist64 (Name:4 + Type:1 + Sect:1 + Desc:2 + Value:8)
const nlist64Size = 16

// parseNlist64 parses an Nlist64 name index and value from raw little-endian bytes.
func parseNlist64(b []byte) (name uint32, value uint64) {
	name = binary.LittleEndian.Uint32(b)
	value = binary.LittleEndian.Uint64(b[8:])
	return
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
