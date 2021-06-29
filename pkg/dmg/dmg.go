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
	"io/ioutil"
	"os"
	"strings"

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

type UDIFChecksumType uint32

const (
	NONE_TYPE  UDIFChecksumType = 0
	CRC32_TYPE UDIFChecksumType = 2
)

type UDIFChecksum struct {
	Type UDIFChecksumType
	Size uint32
	Data [32]uint32
}

const (
	udifRFSignature = "koly"
	udifRFVersion   = 4
)

type UDIFResourceFileFlag uint32

const (
	Flattened       UDIFResourceFileFlag = 0x00000001
	InternetEnabled UDIFResourceFileFlag = 0x00000004
)

// UDIFResourceFile - Universal Disk Image Format (UDIF)
type UDIFResourceFile struct {
	Signature             udifSignature // magic 'koly'
	Version               uint32        // 4 (as of 2013)
	HeaderSize            uint32        // sizeof(this) =  512 (as of 2013)
	Flags                 UDIFResourceFileFlag
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

type UDIFBlockChunkType uint32

const (
	ZERO_FILL       UDIFBlockChunkType = 0x00000000
	UNCOMPRESSED    UDIFBlockChunkType = 0x00000001
	IGNORED         UDIFBlockChunkType = 0x00000002 // Sparse (used for Apple_Free)
	COMPRESS_ADC    UDIFBlockChunkType = 0x80000004
	COMPRESS_ZLIB   UDIFBlockChunkType = 0x80000005
	COMPRESSS_BZ2   UDIFBlockChunkType = 0x80000006
	COMPRESSS_LZFSE UDIFBlockChunkType = 0x80000007
	COMPRESSS_LZMA  UDIFBlockChunkType = 0x80000008
	COMMENT         UDIFBlockChunkType = 0x7ffffffe
	LAST_BLOCK      UDIFBlockChunkType = 0xffffffff
)

func (i UDIFBlockChunkType) String() string {
	switch i {
	case ZERO_FILL:
		return "ZERO_FILL"
	case UNCOMPRESSED:
		return "UNCOMPRESSED"
	case IGNORED:
		return "IGNORED"
	case COMPRESS_ADC:
		return "COMPRESS_ADC"
	case COMPRESS_ZLIB:
		return "COMPRESS_ZLIB"
	case COMPRESSS_BZ2:
		return "COMPRESSS_BZ2"
	case COMPRESSS_LZFSE:
		return "COMPRESSS_LZFSE"
	case COMPRESSS_LZMA:
		return "COMPRESSS_LZMA"
	case COMMENT:
		return "COMMENT"
	case LAST_BLOCK:
		return "LAST_BLOCK"
	default:
		return "UNKNOWN"
	}
}

type UDIFBlockChunk struct {
	Type             UDIFBlockChunkType
	Comment          uint32
	StartSector      uint64 // Logical chunk offset and length, in sectors.
	SectorCount      uint64
	CompressedOffset uint64 // Compressed offset and length, in bytes.
	CompressedLength uint64
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

type UDIFBlockData struct {
	Name string
	udifBlockData
	Chunks []UDIFBlockChunk
}

// DecompressBlkxChunks decompresses the chunks for a given block
func (d *DMG) DecompressBlkxChunks(blkName, outputFile string) ([]byte, error) {

	for _, block := range d.Blocks {
		if strings.Contains(block.Name, blkName) {
			fo, err := os.Create(outputFile)
			if err != nil {
				return nil, err
			}
			defer func() {
				if err := fo.Close(); err != nil {
					panic(err)
				}
			}()
			w := bufio.NewWriter(fo)

			for _, chunk := range block.Chunks {
				switch chunk.Type {
				case ZERO_FILL:
					// write a chunk
					if _, err := w.Write(make([]byte, chunk.CompressedLength)); err != nil {
						return nil, err
					}
				case UNCOMPRESSED:
					d.sr.Seek(int64(chunk.CompressedOffset), io.SeekStart)
					buff := make([]byte, chunk.CompressedLength)
					if err := binary.Read(d.sr, binary.BigEndian, &buff); err != nil {
						return nil, err
					}
					// write a chunk
					if _, err := w.Write(buff); err != nil {
						return nil, err
					}
				case IGNORED:
					continue
				case COMPRESS_ADC:
					return nil, fmt.Errorf("COMPRESS_ADC is currently unsupported")
				case COMPRESS_ZLIB:
					d.sr.Seek(int64(chunk.CompressedOffset), io.SeekStart)
					buff := make([]byte, chunk.CompressedLength)
					if err := binary.Read(d.sr, binary.BigEndian, &buff); err != nil {
						return nil, err
					}

					r, err := zlib.NewReader(bytes.NewReader(buff))
					if err != nil {
						return nil, err
					}
					defer r.Close()

					dat, err := ioutil.ReadAll(r)
					if err != nil {
						return nil, err
					}
					// write a chunk
					if _, err := w.Write(dat); err != nil {
						return nil, err
					}
				case COMPRESSS_BZ2:
					d.sr.Seek(int64(chunk.CompressedOffset), io.SeekStart)
					buff := make([]byte, chunk.CompressedLength)
					if err := binary.Read(d.sr, binary.BigEndian, &buff); err != nil {
						return nil, err
					}
					dat, err := ioutil.ReadAll(bzip2.NewReader(bytes.NewReader(buff)))
					if err != nil {
						return nil, err
					}
					// write a chunk
					if _, err := w.Write(dat); err != nil {
						return nil, err
					}
				case COMPRESSS_LZFSE:
					d.sr.Seek(int64(chunk.CompressedOffset), io.SeekStart)
					buff := make([]byte, chunk.CompressedLength)
					if err := binary.Read(d.sr, binary.BigEndian, &buff); err != nil {
						return nil, err
					}
					decompressed := lzfse.DecodeBuffer(buff)
					// write a chunk
					if _, err := w.Write(decompressed); err != nil {
						return nil, err
					}
				case COMPRESSS_LZMA:
					return nil, fmt.Errorf("COMPRESSS_LZMA is currently unsupported")
				case COMMENT:
					continue // TODO: how to parse comments?
				case LAST_BLOCK:
					if err = w.Flush(); err != nil {
						return nil, err
					}
				default:
					return nil, fmt.Errorf("chuck has unsupported compression type: %#x (%s)", chunk.Type, chunk.Type)
				}
			}
			return nil, nil
		}
	}

	return nil, fmt.Errorf("no blkx matched name %s", blkName)
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
func NewDMG(r io.ReaderAt) (*DMG, error) {

	d := new(DMG)
	d.sr = io.NewSectionReader(r, 0, 1<<63-1)

	d.sr.Seek(int64(-binary.Size(d.Footer)), io.SeekEnd)

	if err := binary.Read(d.sr, binary.BigEndian, &d.Footer); err != nil {
		return nil, err
	}

	// TODO: parse Code Signnature

	d.sr.Seek(int64(d.Footer.PlistOffset), io.SeekStart)

	pdata := make([]byte, d.Footer.PlistLength)
	if err := binary.Read(d.sr, binary.BigEndian, &pdata); err != nil {
		return nil, err
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

		if err := binary.Read(r, binary.BigEndian, &bdata.udifBlockData); err != nil {
			return nil, err
		}

		for i := 0; i < int(bdata.udifBlockData.ChunkCount); i++ {
			var chunk UDIFBlockChunk
			binary.Read(r, binary.BigEndian, &chunk)
			bdata.Chunks = append(bdata.Chunks, chunk)
		}

		d.Blocks = append(d.Blocks, bdata)
	}

	// _, err = d.DecompressBlkxChunks("Apple_APFS", "Apple_APFS")
	// if err != nil {
	// 	return nil, err
	// }

	return d, nil
}
