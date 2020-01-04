package dyld

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/macho"
	"github.com/pkg/errors"
)

// CacheImage represents a dyld dylib image.
type CacheImage struct {
	Name         string
	Index        uint32
	Info         CacheImageInfo
	LocalSymbols []*CacheLocalSymbol64
	CacheLocalSymbolsEntry
	CacheImageInfoExtra
	CacheImageTextInfo
	Initializer    uint64
	DOFSectionAddr uint64
	DOFSectionSize uint32
	RangeStartAddr uint64
	RangeSize      uint32

	// Embed ReaderAt for ReadAt method.
	// Do not embed SectionReader directly
	// to avoid having Read and Seek.
	// If a client wants Read and Seek it must use
	// Open() to avoid fighting over the seek offset
	// with other clients.
	io.ReaderAt
	sr *io.SectionReader
}

// Data reads and returns the contents of the dylib's Mach-O.
func (i *CacheImage) Data() ([]byte, error) {
	dat := make([]byte, i.sr.Size())
	n, err := i.sr.ReadAt(dat, 0)
	if n == len(dat) {
		err = nil
	}
	return dat[0:n], err
}

// Open returns a new ReadSeeker reading the dylib's Mach-O data.
func (i *CacheImage) Open() io.ReadSeeker { return io.NewSectionReader(i.sr, 0, 1<<63-1) }

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
