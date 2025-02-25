package ftab

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/blacktop/ipsw/pkg/lzfse"
	"github.com/dustin/go-humanize"
)

var (
	ErrInvalidMagic   = errors.New("invalid ftab magic")
	ErrInvalidVersion = errors.New("unsupported ftab version")
)

const FtabMagic uint64 = 0x62617466736f6b72 // "rkosftab" in ASCII

// Header represents the header of an ftab file
type Header struct {
	Unknown    [8]uint32
	Magic      uint64 // 'rkosftab'
	NumEntries uint32
	Version    uint32 // ? always 0
}

// EntryHeader represents a single entry in an ftab file
type EntryHeader struct {
	Tag    [4]byte
	Offset uint32
	Size   uint32
	_      uint32
}

type CompressedEntry struct {
	ID             uint32
	OriginalSize   uint32
	CompressedSize uint32
}

type Entry struct {
	EntryHeader
	r      io.ReaderAt
	offset int64 // Track current read position
}

var _ io.Reader = (*Entry)(nil)

// Read implements the io.Reader interface for Entry
func (e *Entry) Read(p []byte) (n int, err error) {
	if e.offset >= int64(e.Size) {
		return 0, io.EOF
	}

	remaining := int64(e.Size) - e.offset
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}

	n, err = e.r.ReadAt(p, e.offset)
	e.offset += int64(n)

	if err == io.EOF && n > 0 && e.offset < int64(e.Size) {
		err = nil
	}

	return
}

func (e *Entry) IsCompressed() (*CompressedEntry, bool) {
	sr := io.NewSectionReader(e.r, 0, 1<<63-1)
	var ce CompressedEntry
	if err := binary.Read(sr, binary.LittleEndian, &ce); err != nil {
		return nil, false
	}
	magic := make([]byte, 4)
	if err := binary.Read(sr, binary.LittleEndian, &magic); err != nil {
		return nil, false
	}
	if !bytes.Equal(magic, []byte("bvx2")) {
		return nil, false
	}
	return &ce, true
}

func (e *Entry) Decompress() ([]byte, error) {
	if _, ok := e.IsCompressed(); !ok {
		return nil, errors.New("entry is not compressed")
	}

	compressedData, err := io.ReadAll(e)
	if err != nil {
		return nil, err
	}

	var cmp CompressedEntry
	if err := binary.Read(bytes.NewReader(compressedData), binary.LittleEndian, &cmp); err != nil {
		return nil, err
	}

	compressedData = compressedData[binary.Size(cmp):]

	if !bytes.Contains(compressedData[:4], []byte("bvx2")) {
		return nil, errors.New("invalid lzfse magic")
	}
	return lzfse.NewDecoder(compressedData).DecodeBuffer()
}

// Ftab represents a parsed ftab file
type Ftab struct {
	Header  Header
	Entries []*Entry
	Ticket  []byte // Optional ApTicket data for signature verification

	closer io.Closer
}

// Open opens an ftab file from the given path
func Open(path string) (*Ftab, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	ftab, err := Parse(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	ftab.closer = f
	return ftab, nil
}

func (f *Ftab) Close() error {
	if f.closer != nil {
		return f.closer.Close()
	}
	return nil
}

// Parse parses an ftab from the given reader
func Parse(r io.ReaderAt) (*Ftab, error) {
	sr := io.NewSectionReader(r, 0, 1<<63-1)

	var ftab Ftab
	if err := binary.Read(sr, binary.LittleEndian, &ftab.Header); err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	if ftab.Header.Magic != FtabMagic {
		return nil, ErrInvalidMagic
	}
	if ftab.Header.Version != 0 {
		return nil, ErrInvalidVersion
	}

	for range ftab.Header.NumEntries {
		var entry Entry
		if err := binary.Read(sr, binary.LittleEndian, &entry.EntryHeader); err != nil {
			return nil, fmt.Errorf("failed to read entries: %w", err)
		}
		entry.r = io.NewSectionReader(r, int64(entry.Offset), int64(entry.Size))
		ftab.Entries = append(ftab.Entries, &entry)
	}

	return &ftab, nil
}

// Dump prints the contents of the ftab to stdout
func (f *Ftab) String() string {
	var buf bytes.Buffer
	buf.WriteString("FTAB Header:\n")
	buf.WriteString(fmt.Sprintf("  Magic:   %#x (%s)\n", f.Header.Magic, "rkosftab"))
	buf.WriteString(fmt.Sprintf("  Version: %d\n", f.Header.Version))
	buf.WriteString(fmt.Sprintf("  Entries: %d\n", f.Header.NumEntries))
	buf.WriteString("FTAB Entries:\n")
	for _, entry := range f.Entries {
		buf.WriteString(fmt.Sprintf("  %s: %#08x-%#08x (%s)\n", entry.Tag, entry.Offset, entry.Offset+entry.Size, humanize.Bytes(uint64(entry.Size))))
	}
	return buf.String()
}

// GetEntryByName returns the entry with the given name, or nil if not found
func (f *Ftab) GetEntryByName(name string) *Entry {
	for _, entry := range f.Entries {
		if string(entry.Tag[:]) == name {
			return entry
		}
	}
	return nil
}

// GetEntryByOffset returns the entry containing the given offset, or nil if not found
func (f *Ftab) GetEntryByOffset(offset uint32) *Entry {
	for _, entry := range f.Entries {
		if offset >= entry.Offset && offset < entry.Offset+entry.Size {
			return entry
		}
	}
	return nil
}
