package extract

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/apex/log"
	apfs "github.com/blacktop/go-apfs"
	"github.com/blacktop/go-apfs/pkg/disk/dmg"
	"github.com/blacktop/go-apfs/pkg/disk/gpt"
	"github.com/blacktop/go-apfs/types"
	"github.com/blacktop/ipsw/internal/atomicfile"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/pkg/aea"
)

// Ranged mode is explicit: unsupported layouts are errors, never an implicit
// full-image download. It owns no mount or disk-image temporary file.
// zr is the already-parsed remote archive; only member data goes through the
// range reader.
func extractRemoteDMGRanged(c *Config, zr *zip.Reader, name, destination, pemDB string, pattern *regexp.Regexp) ([]string, error) {
	members := matchingZipFileName(zr.File, name)
	if len(members) != 1 {
		return nil, fmt.Errorf("expected exactly one ZIP member %s, found %d", name, len(members))
	}
	member := members[0]
	if member.Method != zip.Store || member.CompressedSize64 != member.UncompressedSize64 {
		return nil, fmt.Errorf("ranged extraction requires a stored ZIP member: %s", name)
	}
	remote, err := download.NewRangeReader(c.URL, &download.RemoteConfig{Client: c.remoteHTTPClient()})
	if err != nil {
		return nil, err
	}
	defer func() {
		requests, bytes := remote.Stats()
		log.Infof("Ranged %s: %d requests, %d bytes downloaded (IPSW: %d bytes)", name, requests, bytes, remote.Size())
	}()
	offset, err := member.DataOffset()
	if err != nil {
		return nil, err
	}
	if offset < 0 || offset > remote.Size() || member.CompressedSize64 > uint64(remote.Size()-offset) {
		return nil, fmt.Errorf("ZIP member outside archive")
	}
	size := int64(member.UncompressedSize64)
	var source io.ReaderAt = io.NewSectionReader(remote, offset, size)
	magic := make([]byte, 4)
	if _, err := source.ReadAt(magic, 0); err != nil {
		return nil, err
	}
	if string(magic) == aea.Magic {
		var key []byte
		if c.AEAKey != "" {
			key, err = base64.StdEncoding.DecodeString(strings.TrimPrefix(c.AEAKey, "base64:"))
		} else {
			metadata, e := aea.ReadMetadata(source, size)
			if e != nil {
				return nil, e
			}
			key, err = metadata.SymmetricKey(nil, pemDB, c.Proxy, c.Insecure)
		}
		if err != nil {
			return nil, fmt.Errorf("resolve AEA key: %w", err)
		}
		reader, err := aea.NewReader(source, size, key)
		if err != nil {
			return nil, err
		}
		source = reader
		size = reader.Size()
	}
	// UDIF images remain random-access through go-apfs's bounded chunk cache.
	if size >= 512 {
		footer := make([]byte, 4)
		if _, err := source.ReadAt(footer, size-512); err != nil {
			return nil, err
		}
		if string(footer) == "koly" {
			image, err := dmg.NewDMG(io.NewSectionReader(source, 0, size))
			if err != nil {
				return nil, err
			}
			if err := image.Load(); err != nil {
				return nil, err
			}
			source = image
			// DMG reads are relative to its APFS partition; the whole-image size
			// is an upper bound that the APFS reader clamps to the block count.
			size = int64(image.GetSize())
		}
	}
	source, size, err = apfsPartition(source, size)
	if err != nil {
		return nil, err
	}
	filesystem, err := apfs.OpenReader(source, size)
	if err != nil {
		return nil, fmt.Errorf("ranged APFS %s: %w", name, err)
	}
	if err := os.MkdirAll(destination, 0755); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(destination)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	matcher := newPrefixMatcher(pattern.String())
	var artifacts []string
	ancestors := map[uint64]bool{}
	var walk func(uint64, string, int) error
	walk = func(id uint64, dir string, depth int) error {
		if depth > maxRangedDepth || ancestors[id] {
			return fmt.Errorf("APFS directory cycle or depth limit")
		}
		ancestors[id] = true
		defer delete(ancestors, id)
		entries, err := filesystem.ReadDirID(id)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			relative := path.Join(dir, entry.Name)
			if entry.Type == uint16(types.DT_DIR) {
				if !matcher.directory(relative) {
					continue
				}
				if err := walk(entry.ID, relative, depth+1); err != nil {
					return err
				}
				continue
			}
			// Physical regular-file paths only; symlink aliases are deliberately not followed.
			if entry.Type != uint16(types.DT_REG) || (!pattern.MatchString(relative) && !pattern.MatchString("/"+relative)) {
				continue
			}
			file, err := filesystem.OpenFileID(entry.ID)
			if err != nil {
				return fmt.Errorf("open %s: %w", relative, err)
			}
			if err := writeRangedFile(root, relative, file); err != nil {
				return err
			}
			artifacts = append(artifacts, filepath.Join(destination, filepath.FromSlash(relative)))
		}
		return nil
	}
	// On failure the files already published are still reported with the error.
	err = walk(types.ROOT_DIR_INO_NUM, "", 0)
	return artifacts, err
}

// maxRangedDepth bounds walk recursion. macOS limits a path to 1024 bytes, so
// no reachable directory is nested deeper than this.
const maxRangedDepth = 512

// apfsPartition narrows a GPT image to its APFS partition; a naked APFS
// container is returned unchanged.
func apfsPartition(source io.ReaderAt, size int64) (io.ReaderAt, int64, error) {
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

const rangedCopyBuffer = 4 << 20

// os.Root confines the temporary file and the rename, including pre-existing
// symlinks in the destination. A partially decoded file is never published.
// The output carries the image's permission bits, not its setuid, setgid or
// sticky bits.
func writeRangedFile(root *os.Root, name string, file *apfs.File) error {
	name = filepath.FromSlash(name)
	if err := root.MkdirAll(filepath.Dir(name), 0755); err != nil {
		return err
	}
	perm := file.Mode.Perm()
	if perm == 0 {
		perm = 0644
	}
	return atomicfile.WriteRoot(root, name, perm, func(output *os.File) error {
		// WriteRoot applies the umask to a new file and keeps the bits of an
		// existing one; the image's bits win in both cases.
		if err := output.Chmod(perm); err != nil {
			return err
		}
		// A large buffer lets contiguous extents reach the range reader as single
		// requests. The wrapper hides os.File's ReadFrom, which copies in 32 KiB steps.
		buffer := make([]byte, max(1, min(file.Size, rangedCopyBuffer)))
		written, err := io.CopyBuffer(struct{ io.Writer }{output}, io.NewSectionReader(file, 0, file.Size), buffer)
		if err == nil && written != file.Size {
			err = io.ErrUnexpectedEOF
		}
		return err
	})
}
