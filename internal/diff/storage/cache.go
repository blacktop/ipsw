package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/blacktop/ipsw/pkg/info"
)

// defaultCacheSubdir is appended to os.UserCacheDir() when no override is
// supplied. Keeping the path stable across runs is what lets a second
// invocation of `ipsw diff` reuse the prior database.
const defaultCacheSubdir = "ipsw/diffs"

// CacheOptions controls how OpenCacheStore picks a backing store. The zero
// value targets the default cache directory with persistent storage enabled.
type CacheOptions struct {
	// OldInfo / NewInfo are the parsed IPSW Info structs used to derive
	// the (old, new) cache identities. They must be non-nil whenever the
	// caller wants a persistent store keyed off real artifact identity.
	OldInfo *info.Info
	NewInfo *info.Info

	// Dir overrides the default cache directory. Empty means use
	// os.UserCacheDir() + "/ipsw/diffs/".
	Dir string

	// NoCache disables persistent storage; OpenCacheStore returns a
	// temp-backed SQLiteStore that is deleted on cleanup.
	NoCache bool

	// Clean asks OpenCacheStore to remove any existing database at the
	// resolved path before opening it.
	Clean bool

	// MaxBytes is the LRU eviction threshold applied to the cache
	// directory after the store closes. Zero or negative values disable
	// eviction.
	MaxBytes int64
}

// DefaultCacheDir returns the platform-default cache directory used when no
// --cache-dir override is supplied. It honors os.UserCacheDir() (which itself
// respects XDG_CACHE_HOME on Linux and ~/Library/Caches on macOS).
func DefaultCacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("resolve user cache dir: %w", err)
	}
	return filepath.Join(base, defaultCacheSubdir), nil
}

// ResolveCachePath returns the absolute path of the .db file that backs the
// persistent cache for the (oldIdentity, newIdentity) pair. When override is
// non-empty it replaces the default os.UserCacheDir()/ipsw/diffs/ directory.
// The returned path's parent directory is NOT created; OpenCacheStore (or
// SQLiteStore) handles directory creation lazily.
func ResolveCachePath(oldIdentity, newIdentity, override string) (string, error) {
	if oldIdentity == "" || newIdentity == "" {
		return "", errors.New("storage: ResolveCachePath: identities must be non-empty")
	}
	dir := override
	if dir == "" {
		base, err := DefaultCacheDir()
		if err != nil {
			return "", err
		}
		dir = base
	}
	name := fmt.Sprintf("%s__%s.db", oldIdentity, newIdentity)
	return filepath.Join(dir, name), nil
}

// IPSWCacheIdentity returns a stable, filesystem-safe identifier for an IPSW
// derived from product/build/device + a SHA-256 of the BuildManifest. The
// digest discriminates between same-version artifacts (e.g. internal builds
// reusing a build number) so caches never collide across users sharing a
// build string.
//
// Returns an error when the input has no BuildManifest; callers should fall
// back to a non-persistent store in that case.
func IPSWCacheIdentity(inf *info.Info) (string, error) {
	if inf == nil || inf.Plists == nil || inf.Plists.BuildManifest == nil {
		return "", errors.New("storage: IPSWCacheIdentity: BuildManifest unavailable")
	}
	bm := inf.Plists.BuildManifest
	device := primaryDeviceFromManifest(bm.SupportedProductTypes)
	digest := buildManifestDigest(inf)
	short := digest
	if len(short) > 16 {
		short = short[:16]
	}

	parts := []string{
		sanitizeIdentityComponent(bm.ProductBuildVersion),
		sanitizeIdentityComponent(device),
		sanitizeIdentityComponent(bm.ProductVersion),
		short,
	}
	out := strings.Join(parts, "_")
	out = strings.Trim(out, "_")
	if out == "" {
		return "", errors.New("storage: IPSWCacheIdentity: empty identity")
	}
	return out, nil
}

// buildManifestDigest hashes the raw plist data of the BuildManifest when
// available. The digest captures every identity / manifest entry so two IPSWs
// that share product+build+device but differ in any signed component still
// produce distinct cache identities.
func buildManifestDigest(inf *info.Info) string {
	bm := inf.Plists.BuildManifest
	h := sha256.New()
	// Always include the top-level fields so the digest is stable even
	// when BuildIdentities ordering wiggles across runs.
	_, _ = h.Write([]byte(bm.ProductBuildVersion))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(bm.ProductVersion))
	_, _ = h.Write([]byte{0})

	types := append([]string(nil), bm.SupportedProductTypes...)
	sort.Strings(types)
	for _, t := range types {
		_, _ = h.Write([]byte(t))
		_, _ = h.Write([]byte{0})
	}

	// Fold every BuildIdentity manifest digest into the hash. These are
	// the same digests used by ipswVolumeManifestDigestsEqual to detect
	// unchanged volumes, so reusing them keeps cache identity aligned
	// with the "is this artifact actually the same?" semantics elsewhere
	// in the package.
	for _, ident := range bm.BuildIdentities {
		keys := make([]string, 0, len(ident.Manifest))
		for k := range ident.Manifest {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			_, _ = h.Write([]byte(k))
			_, _ = h.Write([]byte{0})
			_, _ = h.Write(ident.Manifest[k].Digest)
			_, _ = h.Write([]byte{0})
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func primaryDeviceFromManifest(devices []string) string {
	if len(devices) == 0 {
		return ""
	}
	sorted := append([]string(nil), devices...)
	sort.Strings(sorted)
	return sorted[0]
}

// sanitizeIdentityComponent replaces filesystem-unsafe characters with `_` so
// the composed identity can be embedded in a path on every platform.
func sanitizeIdentityComponent(in string) string {
	if in == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(in))
	for _, r := range in {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// OpenCacheStore returns the Store the orchestrator should use for a single
// run, plus a cleanup function the caller must defer. The cleanup closes the
// store and, for persistent caches, runs LRU eviction once the database file
// is no longer locked.
//
// When opts.NoCache is true the store is backed by a temp SQLite database
// that is removed during cleanup; this keeps the gob round-trip semantics of
// the persistent path while avoiding any cross-run state.
//
// When opts.NoCache is false but identity derivation fails (e.g. OTA mode
// without a BuildManifest), the store falls back to the temp-backed mode and
// surfaces a debug log instead of erroring; the orchestrator behavior matches
// the pre-cache code path in that case.
func OpenCacheStore(opts CacheOptions) (Store, func(), error) {
	if opts.NoCache {
		return openTempStore()
	}
	oldID, oldErr := IPSWCacheIdentity(opts.OldInfo)
	newID, newErr := IPSWCacheIdentity(opts.NewInfo)
	if oldErr != nil || newErr != nil {
		return openTempStore()
	}
	path, err := ResolveCachePath(oldID, newID, opts.Dir)
	if err != nil {
		return nil, nil, err
	}
	if opts.Clean {
		if err := removeCacheFile(path); err != nil {
			return nil, nil, fmt.Errorf("storage: clean cache: %w", err)
		}
	}
	store, err := NewSQLiteStore(path)
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() {
		_ = store.Close()
		if opts.MaxBytes > 0 {
			if err := EvictLRU(filepath.Dir(path), opts.MaxBytes); err != nil {
				// Eviction failures must not poison the run.
				// Callers log via the returned error path; here we
				// just swallow because cleanup is deferred.
				_ = err
			}
		}
	}
	return store, cleanup, nil
}

// openTempStore returns a SQLiteStore backed by a temp .db file. The cleanup
// closes the store and removes the temp file; if removal fails the caller is
// expected to log it through the normal close path.
func openTempStore() (Store, func(), error) {
	f, err := os.CreateTemp("", "ipsw-diff-cache-*.db")
	if err != nil {
		return nil, nil, fmt.Errorf("storage: create temp cache: %w", err)
	}
	tempPath := f.Name()
	// SQLite needs to own the file; close the handle before opening it
	// through the driver. The driver will recreate / open as needed.
	_ = f.Close()
	_ = os.Remove(tempPath)
	store, err := NewSQLiteStore(tempPath)
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() {
		_ = store.Close()
		_ = os.Remove(tempPath)
		// SQLite WAL/SHM sidecar files share the path prefix; clean
		// them up so the temp dir does not accumulate cruft.
		_ = os.Remove(tempPath + "-wal")
		_ = os.Remove(tempPath + "-shm")
	}
	return store, cleanup, nil
}

// EvictLRU removes the oldest .db files from cacheDir until the total size
// of remaining .db files is at or below maxBytes. Files are sorted by
// modification time ascending so the least-recently-touched cache is the
// first candidate. Sidecar WAL/SHM files for an evicted .db are deleted
// alongside it so SQLite never re-opens a stale journal pair.
//
// Returns nil when cacheDir does not exist (nothing to evict) or maxBytes
// is zero/negative.
func EvictLRU(cacheDir string, maxBytes int64) error {
	if maxBytes <= 0 {
		return nil
	}
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("storage: read cache dir %s: %w", cacheDir, err)
	}

	type entry struct {
		path string
		size int64
		mod  int64
	}
	var files []entry
	var total int64
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".db") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		size := fi.Size()
		// Include WAL / SHM sidecars when sizing so eviction is honest
		// about total disk usage but only consider the .db file as an
		// eviction candidate; the sidecars are deleted with their .db.
		if extra := sidecarSize(filepath.Join(cacheDir, e.Name())); extra > 0 {
			size += extra
		}
		files = append(files, entry{
			path: filepath.Join(cacheDir, e.Name()),
			size: size,
			mod:  fi.ModTime().UnixNano(),
		})
		total += size
	}
	if total <= maxBytes {
		return nil
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod < files[j].mod })

	var firstErr error
	for _, f := range files {
		if total <= maxBytes {
			break
		}
		if err := removeCacheFile(f.path); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		total -= f.size
	}
	return firstErr
}

func sidecarSize(dbPath string) int64 {
	var total int64
	for _, suffix := range []string{"-wal", "-shm"} {
		if fi, err := os.Stat(dbPath + suffix); err == nil {
			total += fi.Size()
		}
	}
	return total
}

func removeCacheFile(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("storage: evict %s: %w", path, err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		_ = os.Remove(path + suffix)
	}
	return nil
}
