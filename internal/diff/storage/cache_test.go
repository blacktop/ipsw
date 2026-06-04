package storage

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/plist"
)

// fakeInfo builds a minimal *info.Info populated with the BuildManifest fields
// IPSWCacheIdentity reads. extra lets a test mutate a single BuildIdentity
// digest so the resulting identity diverges from the baseline.
func fakeInfo(t *testing.T, product, build, device string, manifestDigest byte) *info.Info {
	t.Helper()
	return &info.Info{
		Plists: &plist.Plists{
			BuildManifest: &plist.BuildManifest{
				ProductBuildVersion:   build,
				ProductVersion:        product,
				SupportedProductTypes: []string{device},
				BuildIdentities: []plist.BuildIdentity{
					{
						Manifest: map[string]plist.IdentityManifest{
							"KernelCache": {
								Digest: []byte{manifestDigest, 0xAA, 0xBB},
							},
						},
					},
				},
			},
		},
	}
}

func TestResolveCachePath(t *testing.T) {
	tests := []struct {
		name     string
		old, new string
		override string
		want     string
		wantErr  bool
	}{
		{
			name:     "override directory wins",
			old:      "old-id",
			new:      "new-id",
			override: "/tmp/custom",
			want:     "/tmp/custom/old-id__new-id.db",
		},
		{
			name:    "empty identity fails",
			old:     "",
			new:     "new-id",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveCachePath(tc.old, tc.new, tc.override)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveCachePath: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolveCachePathDefaultDir(t *testing.T) {
	got, err := ResolveCachePath("a", "b", "")
	if err != nil {
		t.Fatalf("ResolveCachePath: %v", err)
	}
	base, err := DefaultCacheDir()
	if err != nil {
		t.Fatalf("DefaultCacheDir: %v", err)
	}
	want := filepath.Join(base, "a__b.db")
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestIPSWCacheIdentityComposition(t *testing.T) {
	base := fakeInfo(t, "17.0", "21A329", "iPhone15,2", 0x01)
	id, err := IPSWCacheIdentity(base)
	if err != nil {
		t.Fatalf("IPSWCacheIdentity: %v", err)
	}
	// Comma in device names is sanitized to underscore.
	for _, want := range []string{"21A329", "iPhone15_2", "17.0"} {
		if !strings.Contains(id, want) {
			t.Fatalf("identity %q missing component %q", id, want)
		}
	}

	// Identity changes when the BuildManifest digest changes.
	other := fakeInfo(t, "17.0", "21A329", "iPhone15,2", 0xFF)
	otherID, err := IPSWCacheIdentity(other)
	if err != nil {
		t.Fatalf("IPSWCacheIdentity (other): %v", err)
	}
	if id == otherID {
		t.Fatalf("identity collision: %q == %q despite manifest digest change", id, otherID)
	}

	// Same inputs must produce a stable identity across calls.
	again, err := IPSWCacheIdentity(fakeInfo(t, "17.0", "21A329", "iPhone15,2", 0x01))
	if err != nil {
		t.Fatalf("IPSWCacheIdentity (again): %v", err)
	}
	if again != id {
		t.Fatalf("identity not stable: %q != %q", again, id)
	}
}

func TestIPSWCacheIdentityMissingManifest(t *testing.T) {
	if _, err := IPSWCacheIdentity(nil); err == nil {
		t.Fatal("expected error on nil Info")
	}
	if _, err := IPSWCacheIdentity(&info.Info{}); err == nil {
		t.Fatal("expected error on Info without Plists")
	}
}

func TestOpenCacheStoreNoCache(t *testing.T) {
	dir := t.TempDir()
	store, cleanup, err := OpenCacheStore(CacheOptions{
		NoCache: true,
		Dir:     dir, // ignored when NoCache is true
	})
	if err != nil {
		t.Fatalf("OpenCacheStore: %v", err)
	}
	if store == nil {
		t.Fatal("nil store")
	}
	if cleanup == nil {
		t.Fatal("nil cleanup")
	}

	scope := baseScope()
	if err := store.Put(scope, "row", payload{Path: "x"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	cleanup()

	// Persistent cache dir must remain empty because NoCache=true used a
	// temp file path elsewhere.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".db") {
			t.Fatalf("unexpected .db file in override dir: %s", e.Name())
		}
	}
}

func TestOpenCacheStorePersistent(t *testing.T) {
	dir := t.TempDir()
	store, cleanup, err := OpenCacheStore(CacheOptions{
		OldInfo: fakeInfo(t, "17.0", "21A329", "iPhone15,2", 0x01),
		NewInfo: fakeInfo(t, "17.1", "21B70", "iPhone15,2", 0x02),
		Dir:     dir,
	})
	if err != nil {
		t.Fatalf("OpenCacheStore: %v", err)
	}
	if err := store.Put(baseScope(), "row", payload{Path: "x"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	cleanup()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var dbs []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".db") {
			dbs = append(dbs, e.Name())
		}
	}
	if len(dbs) != 1 {
		t.Fatalf("expected 1 .db file, got %v", dbs)
	}
}

func TestOpenCacheStoreClean(t *testing.T) {
	dir := t.TempDir()
	oldInfo := fakeInfo(t, "17.0", "21A329", "iPhone15,2", 0x01)
	newInfo := fakeInfo(t, "17.1", "21B70", "iPhone15,2", 0x02)
	oldID, _ := IPSWCacheIdentity(oldInfo)
	newID, _ := IPSWCacheIdentity(newInfo)
	path, _ := ResolveCachePath(oldID, newID, dir)

	// Pre-seed a sentinel file at the resolved path so the test can prove
	// --clean removed it.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	store, cleanup, err := OpenCacheStore(CacheOptions{
		OldInfo: oldInfo,
		NewInfo: newInfo,
		Dir:     dir,
		Clean:   true,
	})
	if err != nil {
		t.Fatalf("OpenCacheStore: %v", err)
	}
	defer cleanup()
	_ = store

	// The original file content is gone; a freshly opened SQLite header
	// is in its place.
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.HasPrefix(string(got), "stale") {
		t.Fatalf("--clean did not remove the existing DB")
	}
}

func TestEvictLRU(t *testing.T) {
	dir := t.TempDir()

	// Create 4 .db files: oldest 100 bytes, then 200, 300, 400 bytes.
	now := time.Now()
	type spec struct {
		name string
		size int
		age  time.Duration
	}
	specs := []spec{
		{"oldest.db", 100, 4 * time.Hour},
		{"old.db", 200, 3 * time.Hour},
		{"new.db", 300, 2 * time.Hour},
		{"newest.db", 400, time.Hour},
	}
	for _, s := range specs {
		p := filepath.Join(dir, s.name)
		if err := os.WriteFile(p, make([]byte, s.size), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		mod := now.Add(-s.age)
		if err := os.Chtimes(p, mod, mod); err != nil {
			t.Fatalf("Chtimes: %v", err)
		}
	}

	// Cap at 500 bytes -> must evict oldest.db (100) and old.db (200),
	// leaving new.db (300) + newest.db (400) = 700 ... still over cap.
	// After evicting old.db (200) we are at 1000-100-200 = 700 > 500.
	// Loop must keep evicting next-oldest until <= cap. So new.db (300)
	// must also go, leaving 400 (newest.db).
	if err := EvictLRU(dir, 500); err != nil {
		t.Fatalf("EvictLRU: %v", err)
	}
	survivors := listDBs(t, dir)
	wantSurvivors := []string{"newest.db"}
	if !equalStrings(survivors, wantSurvivors) {
		t.Fatalf("survivors=%v want=%v", survivors, wantSurvivors)
	}
}

func TestEvictLRUUnderCapNoop(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "small.db"), make([]byte, 10), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := EvictLRU(dir, 1024); err != nil {
		t.Fatalf("EvictLRU: %v", err)
	}
	if got := listDBs(t, dir); !equalStrings(got, []string{"small.db"}) {
		t.Fatalf("expected small.db to survive, got %v", got)
	}
}

func TestEvictLRUMissingDir(t *testing.T) {
	if err := EvictLRU(filepath.Join(t.TempDir(), "nope"), 1024); err != nil {
		t.Fatalf("EvictLRU on missing dir: %v", err)
	}
}

func TestEvictLRUZeroDisabled(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "big.db")
	if err := os.WriteFile(p, make([]byte, 4096), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := EvictLRU(dir, 0); err != nil {
		t.Fatalf("EvictLRU(0): %v", err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("file evicted with max=0: %v", err)
	}
}

// TestEvictLRURemovesSidecars proves that evicting a .db file also removes
// its SQLite -wal and -shm sidecars so the next open does not pick up a
// stale journal pair.
func TestEvictLRURemovesSidecars(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "evict.db")
	if err := os.WriteFile(dbPath, make([]byte, 4096), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.WriteFile(dbPath+suffix, make([]byte, 32), 0o644); err != nil {
			t.Fatalf("WriteFile sidecar: %v", err)
		}
	}
	if err := EvictLRU(dir, 100); err != nil {
		t.Fatalf("EvictLRU: %v", err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if _, err := os.Stat(dbPath + suffix); err == nil {
			t.Fatalf("expected %s removed", dbPath+suffix)
		}
	}
}

func listDBs(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".db") {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
