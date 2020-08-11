package dyld

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/buffer"
	"github.com/pkg/errors"
)

type rangeEntry struct {
	StartAddr  uint64
	FileOffset uint64
	Size       uint32
}

type patchableExport struct {
	Name           string
	OffsetOfImpl   uint32
	PatchLocations []CachePatchableLocation
}

// CacheImage represents a dyld dylib image.
type CacheImage struct {
	Name         string
	Index        uint32
	Info         CacheImageInfo
	LocalSymbols []*CacheLocalSymbol64
	CacheLocalSymbolsEntry
	CacheImageInfoExtra
	CacheImageTextInfo
	Initializer      uint64
	DOFSectionAddr   uint64
	DOFSectionSize   uint32
	RangeEntries     []rangeEntry
	PatchableExports []patchableExport

	// Embed ReaderAt for ReadAt method.
	// Do not embed SectionReader directly
	// to avoid having Read and Seek.
	// If a client wants Read and Seek it must use
	// Open() to avoid fighting over the seek offset
	// with other clients.
	// io.ReaderAt
	sr *io.SectionReader
}

// Data reads and returns the contents of the dylib's Mach-O.
func (i *CacheImage) Data() ([]byte, error) {
	// var buff bytes.Buffer
	buff := buffer.NewReadWriteBuffer(int(i.TextSegmentSize), 1<<63-1)

	i.sr.Seek(0, io.SeekStart)

	for idx, rEntry := range i.RangeEntries {
		dat := make([]byte, rEntry.Size)
		n, err := i.sr.ReadAt(dat, int64(rEntry.FileOffset))
		if err != nil {
			return nil, err
		}
		if n != len(dat) {
			return nil, fmt.Errorf("failed to read all the bytes")
		}
		if idx == 0 {
			n, err = buff.WriteAt(dat, 0)
			if err != nil {
				return nil, err
			}
		}
		n, err = buff.WriteAt(dat, int64(rEntry.FileOffset))
		// n, err = buff.WriteAt(dat, int64(rEntry.StartAddr-i.Info.Address))
		if err != nil {
			return nil, err
		}
		if n != len(dat) {
			return nil, fmt.Errorf("failed to write all the bytes")
		}
	}

	return buff.Bytes(), nil
}

// SegmentData reads the __TEXT header and returns the contents of the dylib's Mach-O.
func (i *CacheImage) SegmentData() ([]byte, error) {
	// var buff bytes.Buffer
	buff := buffer.NewReadWriteBuffer(int(i.TextSegmentSize), 1<<63-1)

	i.sr.Seek(0, io.SeekStart)

	m, err := i.GetPartialMacho()
	if err != nil {
		return nil, err
	}
	for idx, seg := range m.Segments() {
		dat := make([]byte, seg.Filesz)
		n, err := i.sr.ReadAt(dat, int64(seg.Offset))
		if err != nil {
			return nil, err
		}
		if n != len(dat) {
			return nil, fmt.Errorf("failed to read all the bytes")
		}
		if idx == 0 {
			n, err = buff.WriteAt(dat, 0)
			if err != nil {
				return nil, err
			}
		}
		n, err = buff.WriteAt(dat, int64(seg.Offset))
		// n, err = buff.WriteAt(dat, int64(rEntry.StartAddr-i.Info.Address))
		if err != nil {
			return nil, err
		}
		if n != len(dat) {
			return nil, fmt.Errorf("failed to write all the bytes")
		}
	}

	return buff.Bytes(), nil
}

// Open returns a new ReadSeeker reading the dylib's Mach-O data.
func (i *CacheImage) Open() io.ReadSeeker {
	return io.NewSectionReader(i.sr, int64(i.DylibOffset), 1<<63-1)
}

// GetPartialMacho parses dyld image header as a partial MachO
func (i *CacheImage) GetPartialMacho() (*macho.File, error) {
	r := io.NewSectionReader(i.sr, int64(i.DylibOffset), int64(i.TextSegmentSize))
	m, err := macho.NewFile(r, types.LC_SEGMENT_64, types.LC_DYLD_INFO, types.LC_DYLD_INFO_ONLY, types.LC_ID_DYLIB, types.LC_DYLD_EXPORTS_TRIE)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// GetMacho parses dyld image as a MachO
func (i *CacheImage) GetMacho() (*macho.File, error) {
	dat, err := i.SegmentData()
	if err != nil {
		return nil, err
	}
	m, err := macho.NewFile(bytes.NewReader(dat))
	if err != nil {
		return nil, err
	}
	return m, nil
}

// Strings returns all the dylib image's cstring literals
func (i *CacheImage) Strings() []string {

	var imgStrings []string

	imgData, err := i.Data()
	if err != nil {
		return nil
	}

	m, err := macho.NewFile(bytes.NewReader(imgData))
	if err != nil {
		log.Error(errors.Wrap(err, "failed to parse macho").Error())
	}
	defer m.Close()

	imgReader := i.Open()

	for _, sec := range m.Sections {

		if sec.Flags.IsCstringLiterals() {
			fmt.Printf("%s %s\n", sec.Seg, sec.Name)
			// csr := bufio.NewReader(sec.Open())
			data := make([]byte, sec.Size)

			imgReader.Seek(int64(sec.Offset), os.SEEK_SET)
			imgReader.Read(data)

			csr := bytes.NewBuffer(data[:])

			for {
				s, err := csr.ReadString('\x00')

				if err == io.EOF {
					break
				}

				if err != nil {
					log.Fatal(err.Error())
				}

				if len(s) > 0 {
					imgStrings = append(imgStrings, strings.Trim(s, "\x00"))
					// fmt.Printf("%s: %#v\n", i.Name, strings.Trim(s, "\x00"))
				}
			}
		}
	}

	return imgStrings
}
