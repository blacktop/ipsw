package remote

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	apfs "github.com/blacktop/go-apfs"
	"github.com/blacktop/go-apfs/pkg/disk/dmg"
	"github.com/blacktop/go-apfs/pkg/disk/gpt"
	"github.com/blacktop/ipsw/pkg/aea"
)

// AEAConfig says how the key of an AEA encrypted disk image is obtained. The
// zero value fetches it with the metadata of the image.
type AEAConfig struct {
	B64SymKey string // with or without a "base64:" prefix
	PemDB     string
	Proxy     string
	Insecure  bool
}

// OpenZipAPFS opens the APFS container in a disk image that is a stored member
// of the ZIP archive of size bytes read through remote. The image may be AEA
// encrypted, a UDIF or a raw image, with or without a GPT.
func OpenZipAPFS(remote io.ReaderAt, size int64, member *zip.File, config *AEAConfig) (*apfs.Reader, error) {
	if member.Method != zip.Store || member.CompressedSize64 != member.UncompressedSize64 {
		return nil, fmt.Errorf("ranged extraction requires a stored ZIP member: %s", member.Name)
	}
	offset, err := member.DataOffset()
	if err != nil {
		return nil, err
	}
	if offset < 0 || offset > size || member.CompressedSize64 > uint64(size-offset) {
		return nil, fmt.Errorf("ZIP member outside archive")
	}
	size = int64(member.UncompressedSize64)
	source, size, err := apfsSource(io.NewSectionReader(remote, offset, size), size, config)
	if err != nil {
		return nil, err
	}
	filesystem, err := apfs.OpenReader(source, size)
	if err != nil {
		return nil, fmt.Errorf("ranged APFS %s: %w", member.Name, err)
	}
	return filesystem, nil
}

// OpenAPFS is OpenZipAPFS for a disk image that is not a ZIP member.
func OpenAPFS(image io.ReaderAt, size int64, config *AEAConfig) (*apfs.Reader, error) {
	source, size, err := apfsSource(image, size, config)
	if err != nil {
		return nil, err
	}
	return apfs.OpenReader(source, size)
}

func apfsSource(source io.ReaderAt, size int64, config *AEAConfig) (io.ReaderAt, int64, error) {
	if config == nil {
		config = &AEAConfig{}
	}
	magic := make([]byte, 4)
	if _, err := source.ReadAt(magic, 0); err != nil {
		return nil, 0, err
	}
	if string(magic) == aea.Magic {
		var key []byte
		var err error
		if config.B64SymKey != "" {
			key, err = base64.StdEncoding.DecodeString(strings.TrimPrefix(config.B64SymKey, "base64:"))
		} else {
			metadata, e := aea.ReadMetadata(source, size)
			if e != nil {
				return nil, 0, e
			}
			key, err = metadata.SymmetricKey(nil, config.PemDB, config.Proxy, config.Insecure)
		}
		if err != nil {
			return nil, 0, fmt.Errorf("resolve AEA key: %w", err)
		}
		reader, err := aea.NewReader(source, size, key)
		if err != nil {
			return nil, 0, err
		}
		source = reader
		size = reader.Size()
	}
	// UDIF images remain random-access through go-apfs's bounded chunk cache.
	if size >= 512 {
		footer := make([]byte, 4)
		if _, err := source.ReadAt(footer, size-512); err != nil {
			return nil, 0, err
		}
		if string(footer) == "koly" {
			image, err := dmg.NewDMG(io.NewSectionReader(source, 0, size))
			if err != nil {
				return nil, 0, err
			}
			if err := image.Load(); err != nil {
				return nil, 0, err
			}
			source = image
			// DMG reads are relative to its APFS partition; the whole-image size
			// is an upper bound that the APFS reader clamps to the block count.
			size = int64(image.GetSize())
		}
	}
	return APFSPartition(source, size)
}

// APFSPartition narrows a GPT image to its APFS partition; a naked APFS
// container is returned unchanged.
func APFSPartition(source io.ReaderAt, size int64) (io.ReaderAt, int64, error) {
	var header gpt.Header
	if err := binary.Read(io.NewSectionReader(source, gpt.SectorSize, gpt.SectorSize), binary.LittleEndian, &header); err != nil {
		return nil, 0, err
	}
	if string(header.Signature[:]) != gpt.Signature {
		return source, size, nil
	}
	sectors := uint64(size / gpt.SectorSize)
	if header.EntriesStart > sectors || header.EntriesCount > 4096 || header.EntriesSize < 128 || header.EntriesSize > 4096 ||
		uint64(header.EntriesCount)*uint64(header.EntriesSize) > uint64(size)-header.EntriesStart*gpt.SectorSize {
		return nil, 0, fmt.Errorf("unsupported GPT table")
	}
	table := make([]byte, header.EntriesCount*header.EntriesSize)
	if _, err := source.ReadAt(table, int64(header.EntriesStart*gpt.SectorSize)); err != nil {
		return nil, 0, err
	}
	for ; len(table) > 0; table = table[header.EntriesSize:] {
		var partition gpt.Partition
		if err := binary.Read(bytes.NewReader(table), binary.LittleEndian, &partition); err != nil {
			return nil, 0, err
		}
		if partition.Type.String() != gpt.Apple_APFS {
			continue
		}
		if partition.StartingLBA > partition.EndingLBA || partition.EndingLBA >= sectors {
			return nil, 0, fmt.Errorf("invalid APFS GPT partition")
		}
		size = int64((partition.EndingLBA - partition.StartingLBA + 1) * gpt.SectorSize)
		return io.NewSectionReader(source, int64(partition.StartingLBA*gpt.SectorSize), size), size, nil
	}
	return nil, 0, fmt.Errorf("no APFS partition in GPT")
}
