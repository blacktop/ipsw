package kernelcache

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/apex/log"
)

// A LzssHeader represents the LZSS header
type LzssHeader struct {
	Signature        [8]byte // "complzss"
	Unknown          uint32  // Likely CRC32. But who cares, anyway?
	UncompressedSize uint32
	CompressedSize   uint32
	Unknown1         uint32 // 1
}

// A CompressedCache represents an open compressed kernelcache file.
type CompressedCache struct {
	Header LzssHeader
	Size   int64
	Data   []byte
}

// Open opens the named file using os.Open and prepares it for use as a compressed kernelcache.
func Open(name string) (*CompressedCache, error) {

	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	cc := new(CompressedCache)
	cc.Size = fi.Size()

	dat := make([]byte, 1000)
	_, err = f.Read(dat)
	if err != nil {
		return nil, err
	}

	// find lzss magic
	hStart := bytes.Index(dat, []byte("complzss"))

	// Read entire file header.
	f.Seek(int64(hStart), 0)
	if err := binary.Read(f, binary.BigEndian, &cc.Header); err != nil {
		return nil, err
	}

	// Compressed Size: 17842843, Uncompressed: 35727352. Unknown (CRC?): 0x3f9543fd, Unknown 1: 0x1
	log.Infof("Compressed Size: %d, Uncompressed: %d. Unknown: 0x%x, Unknown 1: 0x%x",
		cc.Header.CompressedSize,
		cc.Header.UncompressedSize,
		cc.Header.Unknown,
		cc.Header.Unknown1,
	)

	// find compressed kernel 0xfeedfa.. start address
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, 0xfeedfacf)
	dStart := bytes.Index(dat, buf)
	log.Infof("found compressed kernel at: %d", dStart)

	if int64(cc.Header.CompressedSize) > cc.Size {
		return nil, fmt.Errorf("compressed_size: %d is greater than file_size: %d", cc.Size, cc.Header.CompressedSize)
	}

	// Read entire file data.
	cc.Data = make([]byte, cc.Size-int64(dStart), int64(cc.Header.CompressedSize))
	n, err := f.ReadAt(cc.Data, int64(dStart-1))
	if err != nil {
		return nil, err
	}
	log.Infof("read %d bytes of data from file", n)

	return cc, nil
}

// ParseMachO parses the kernelcache as a mach-o
func ParseMachO(name string) error {
	f, err := macho.Open(name)
	if err != nil {
		return err
	}

	fmt.Println(f.FileHeader)

	return nil
}
