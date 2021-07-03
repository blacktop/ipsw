// +build darwin,cgo

package dmg

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/apex/log"
	lzfse "github.com/blacktop/go-lzfse"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/go-plist"
)

// DMG apple disk image object
type DMG struct {
	Footer UDIFResourceFile
	Plist  resourceFork
	Nsiz   nsiz
	Blocks []UDIFBlockData

	sr     *io.SectionReader
	closer io.Closer
}

type block struct {
	Attributes string
	Data       []byte
	ID         string
	Name       string
	CFName     string `plist:"CFName,omitempty"`
}

type resourceFork struct {
	ResourceFork map[string][]block `plist:"resource-fork,omitempty"`
}

type volAndUUID struct {
	Name string `plist:"name,omitempty"`
	UUID string `plist:"uuid,omitempty"`
}

type nsiz struct {
	Sha1Digest          []byte       `plist:"SHA-1-digest,omitempty"`
	Sha256Digest        []byte       `plist:"SHA-256-digest,omitempty"`
	VolumeNamesAndUUIDs []volAndUUID `plist:"Volume names and UUIDs,omitempty"`
	BlockChecksum2      int          `plist:"block-checksum-2,omitempty"`
	PartNum             int          `plist:"part-num,omitempty"`
	Version             int          `plist:"version,omitempty"`
}

type udifSignature [4]byte

func (s udifSignature) String() string {
	return string(s[:])
}

type udifChecksumType uint32

const (
	NONE_TYPE  udifChecksumType = 0
	CRC32_TYPE udifChecksumType = 2
)

// UDIFChecksum object
type UDIFChecksum struct {
	Type udifChecksumType
	Size uint32
	Data [32]uint32
}

const (
	udifRFSignature = "koly"
	udifRFVersion   = 4
	udifSectorSize  = 512
)

type udifResourceFileFlag uint32

const (
	Flattened       udifResourceFileFlag = 0x00000001
	InternetEnabled udifResourceFileFlag = 0x00000004
)

// UDIFResourceFile - Universal Disk Image Format (UDIF)
type UDIFResourceFile struct {
	Signature             udifSignature // magic 'koly'
	Version               uint32        // 4 (as of 2013)
	HeaderSize            uint32        // sizeof(this) =  512 (as of 2013)
	Flags                 udifResourceFileFlag
	RunningDataForkOffset uint64
	DataForkOffset        uint64 // usually 0, beginning of file
	DataForkLength        uint64
	RsrcForkOffset        uint64 // resource fork offset and length
	RsrcForkLength        uint64
	SegmentNumber         uint32 // Usually 1, can be 0
	SegmentCount          uint32 // Usually 1, can be 0
	SegmentID             types.UUID

	DataChecksum UDIFChecksum

	PlistOffset uint64 // Offset and length of the blkx plist.
	PlistLength uint64

	Reserved1 [64]byte

	CodeSignatureOffset uint64
	CodeSignatureLength uint64

	Reserved2 [40]byte

	MasterChecksum UDIFChecksum

	ImageVariant uint32 // Unknown, commonly 1
	SectorCount  uint64

	Reserved3 uint32
	Reserved4 uint32
	Reserved5 uint32
}

const (
	udifBDSignature = "mish"
	udifBDVersion   = 1
)

type udifBlockData struct {
	Signature   udifSignature // magic 'mish'
	Version     uint32
	StartSector uint64 // Logical block offset and length, in sectors.
	SectorCount uint64

	DataOffset       uint64
	BuffersNeeded    uint32
	BlockDescriptors uint32

	Reserved1 uint32
	Reserved2 uint32
	Reserved3 uint32
	Reserved4 uint32
	Reserved5 uint32
	Reserved6 uint32

	Checksum UDIFChecksum

	ChunkCount uint32
}

// UDIFBlockData object
type UDIFBlockData struct {
	Name string
	udifBlockData
	Chunks []udifBlockChunk

	sr *io.SectionReader
}

type udifBlockChunkType uint32

const (
	ZERO_FILL       udifBlockChunkType = 0x00000000
	UNCOMPRESSED    udifBlockChunkType = 0x00000001
	IGNORED         udifBlockChunkType = 0x00000002 // Sparse (used for Apple_Free)
	COMPRESS_ADC    udifBlockChunkType = 0x80000004
	COMPRESS_ZLIB   udifBlockChunkType = 0x80000005
	COMPRESSS_BZ2   udifBlockChunkType = 0x80000006
	COMPRESSS_LZFSE udifBlockChunkType = 0x80000007
	COMPRESSS_LZMA  udifBlockChunkType = 0x80000008
	COMMENT         udifBlockChunkType = 0x7ffffffe
	LAST_BLOCK      udifBlockChunkType = 0xffffffff
)

type udifBlockChunk struct {
	Type             udifBlockChunkType
	Comment          uint32
	StartSector      uint64 // Logical chunk offset and length, in sectors.
	SectorCount      uint64
	CompressedOffset uint64 // Compressed offset and length, in bytes.
	CompressedLength uint64
}

func (b *UDIFBlockData) maxChunkSize() int {
	var max int
	for _, chunk := range b.Chunks {
		if max < int(chunk.CompressedLength) {
			max = int(chunk.CompressedLength)
		}
	}
	return max
}

// DecompressChunks decompresses the chunks for a given block and writes them to supplied bufio.Writer
func (b *UDIFBlockData) DecompressChunks(w *bufio.Writer) error {
	var n int
	var total int
	var err error

	buff := make([]byte, 0, b.maxChunkSize())

	for _, chunk := range b.Chunks {
		// TODO: verify chunk (size not greater than block etc)
		switch chunk.Type {
		case ZERO_FILL:
			// write a chunk
			n, err = w.Write(make([]byte, chunk.CompressedLength))
			if err != nil {
				return err
			}
			total += n
			log.Debugf("Wrote %#x bytes of ZERO_FILL data (output size: %#x)", n, total)
		case UNCOMPRESSED:
			buff = buff[:chunk.CompressedLength]
			_, err = b.sr.ReadAt(buff, int64(chunk.CompressedOffset))
			if err != nil {
				return err
			}
			// write a chunk
			n, err = w.Write(buff)
			if err != nil {
				return err
			}
			total += n
			log.Debugf("Wrote %#x bytes of UNCOMPRESSED data (output size: %#x)", n, total)
		case IGNORED:
			// write a chunk
			n, err = w.Write(make([]byte, chunk.SectorCount*udifSectorSize))
			if err != nil {
				return err
			}
			total += n
			log.Debugf("Wrote %#x bytes of IGNORED data (output size: %#x)", n, total)
		case COMPRESS_ADC:
			return fmt.Errorf("COMPRESS_ADC is currently unsupported")
		case COMPRESS_ZLIB:
			buff = buff[:chunk.CompressedLength]
			_, err = b.sr.ReadAt(buff, int64(chunk.CompressedOffset))
			if err != nil {
				return err
			}
			r, err := zlib.NewReader(bytes.NewReader(buff))
			if err != nil {
				return err
			}
			// write a chunk
			n, err := w.ReadFrom(r)
			if err != nil {
				return err
			}
			r.Close()
			total += int(n)
			log.Debugf("Wrote %#x bytes of COMPRESS_ZLIB data (output size: %#x)", n, total)
		case COMPRESSS_BZ2:
			buff = buff[:chunk.CompressedLength]
			if _, err := b.sr.ReadAt(buff, int64(chunk.CompressedOffset)); err != nil {
				return err
			}
			// write a chunk
			n, err := w.ReadFrom(bzip2.NewReader(bytes.NewReader(buff)))
			if err != nil {
				return err
			}
			total += int(n)
			log.Debugf("Wrote %#x bytes of COMPRESSS_BZ2 data (output size: %#x)", n, total)
		case COMPRESSS_LZFSE:
			buff = buff[:chunk.CompressedLength]
			if _, err := b.sr.ReadAt(buff, int64(chunk.CompressedOffset)); err != nil {
				return err
			}
			n, err = w.Write(lzfse.DecodeBuffer(buff))
			if err != nil {
				return err
			}
			total += n
			log.Debugf("Wrote %#x bytes of COMPRESSS_LZFSE data (output size: %#x)", n, total)
		case COMPRESSS_LZMA:
			return fmt.Errorf("COMPRESSS_LZMA is currently unsupported")
		case COMMENT:
			continue // TODO: how to parse comments?
		case LAST_BLOCK:
			if err := w.Flush(); err != nil {
				return err
			}
		default:
			return fmt.Errorf("chuck has unsupported compression type: %#x", chunk.Type)
		}
	}

	return nil
}

// Open opens the named file using os.Open and prepares it for use as a dmg.
func Open(name string) (*DMG, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	ff, err := NewDMG(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	ff.closer = f
	return ff, nil
}

// Close closes the DMG.
// If the DMG was created using NewFile directly instead of Open,
// Close has no effect.
func (d *DMG) Close() error {
	var err error
	if d.closer != nil {
		err = d.closer.Close()
		d.closer = nil
	}
	return err
}

// NewDMG creates a new DMG for accessing a dmg in an underlying reader.
// The dmg is expected to start at position 0 in the ReaderAt.
func NewDMG(r *os.File) (*DMG, error) {

	d := new(DMG)
	d.sr = io.NewSectionReader(r, 0, 1<<63-1)

	if _, err := r.Seek(int64(-binary.Size(UDIFResourceFile{})), io.SeekEnd); err != nil {
		return nil, fmt.Errorf("failed to seek to DMG footer: %v", err)
	}

	if err := binary.Read(r, binary.BigEndian, &d.Footer); err != nil {
		return nil, fmt.Errorf("failed to read DMG footer: %v", err)
	}

	if d.Footer.Signature.String() != udifRFSignature {
		return nil, fmt.Errorf("found unexpected UDIFResourceFile signure: %s, expected: %s", d.Footer.Signature.String(), udifRFSignature)
	}

	// TODO: parse Code Signnature

	r.Seek(int64(d.Footer.PlistOffset), io.SeekStart)

	pdata := make([]byte, d.Footer.PlistLength)
	if err := binary.Read(r, binary.BigEndian, &pdata); err != nil {
		return nil, fmt.Errorf("failed to read DMG plist data: %v", err)
	}

	pl := plist.NewDecoder(bytes.NewReader(pdata))
	if err := pl.Decode(&d.Plist); err != nil {
		return nil, fmt.Errorf("failed to parse DMG plist data: %v\n%s", err, string(pdata[:]))
	}

	if nsiz, ok := d.Plist.ResourceFork["nsiz"]; ok {
		pl = plist.NewDecoder(bytes.NewReader(nsiz[0].Data))
		if err := pl.Decode(&d.Nsiz); err != nil {
			return nil, fmt.Errorf("failed to parse nsiz plist data: %v\n%s", err, string(nsiz[0].Data[:]))
		}
	}

	// TODO: handle 'cSum', 'plst' and 'size' also
	for _, block := range d.Plist.ResourceFork["blkx"] {
		var bdata UDIFBlockData

		r := bytes.NewReader(block.Data)

		bdata.Name = block.Name
		bdata.sr = d.sr

		if err := binary.Read(r, binary.BigEndian, &bdata.udifBlockData); err != nil {
			return nil, fmt.Errorf("failed to read UDIFBlockData in block %s: %v", block.Name, err)
		}

		if bdata.udifBlockData.Signature.String() != udifBDSignature {
			return nil, fmt.Errorf("found unexpected UDIFBlockData signure: %s, expected: %s", bdata.udifBlockData.Signature.String(), udifBDSignature)
		}

		for i := 0; i < int(bdata.udifBlockData.ChunkCount); i++ {
			var chunk udifBlockChunk
			binary.Read(r, binary.BigEndian, &chunk)
			bdata.Chunks = append(bdata.Chunks, chunk)
		}

		d.Blocks = append(d.Blocks, bdata)
	}

	return d, nil
}
