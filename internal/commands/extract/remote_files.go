package extract

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"

	"github.com/apex/log"
	apfs "github.com/blacktop/go-apfs"
	"github.com/blacktop/go-apfs/types"
	"github.com/blacktop/ipsw/internal/atomicfile"
	"github.com/blacktop/ipsw/pkg/remote"
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
	// Checked before the size request so a compressed member costs no round trip.
	if member.Method != zip.Store || member.CompressedSize64 != member.UncompressedSize64 {
		return nil, fmt.Errorf("ranged extraction requires a stored ZIP member: %s", name)
	}
	source, err := remote.NewRangeReader(c.URL, &remote.Config{Client: c.remoteHTTPClient()})
	if err != nil {
		return nil, err
	}
	defer func() {
		requests, bytes := source.Stats()
		log.Infof("Ranged %s: %d requests, %d bytes downloaded (IPSW: %d bytes)", name, requests, bytes, source.Size())
	}()
	filesystem, err := remote.OpenZipAPFS(source, source.Size(), member, &remote.AEAConfig{
		B64SymKey: c.AEAKey, PemDB: pemDB, Proxy: c.Proxy, Insecure: c.Insecure,
	})
	if err != nil {
		return nil, err
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
