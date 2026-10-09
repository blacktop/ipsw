package search

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/testutil"
)

func metalUniversalFixture() []byte {
	const airOffset, airSize, gpuOffset, gpuSize = 48, 88, 144, 32
	data := make([]byte, gpuOffset+gpuSize)
	for idx, word := range []uint32{
		0xcafebabe, 2,
		0x01000017, 13, airOffset, airSize, 3,
		0x01000013, 83, gpuOffset, gpuSize, 4,
	} {
		binary.BigEndian.PutUint32(data[idx*4:], word)
	}
	copy(data[airOffset:], "MTLB")
	binary.LittleEndian.PutUint16(data[airOffset+4:], 0x8001)
	binary.LittleEndian.PutUint16(data[airOffset+6:], 2)
	binary.LittleEndian.PutUint16(data[airOffset+8:], 9)
	binary.LittleEndian.PutUint64(data[airOffset+16:], airSize)
	for pos := airOffset + 24; pos < airOffset+airSize; pos += 16 {
		binary.LittleEndian.PutUint64(data[pos:], airSize)
	}
	for idx, word := range []uint32{0xfeedfacf, 0x01000013, 83, uint32(types.MH_GPU_EXECUTE), 0, 0, 0, 0} {
		binary.LittleEndian.PutUint32(data[gpuOffset+idx*4:], word)
	}
	return data
}

func TestForEachMachoSlicesStrictMetalUniversal(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "no-extension")
	data := metalUniversalFixture()
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	unwantedVisit := errors.New("Metal universal reached Mach-O visitor")
	visit := func(string, []*macho.File) error { return unwantedVisit }
	if err := ForEachMachoSlicesStrict(root, visit); err != nil {
		t.Fatalf("valid mixed Metal container was rejected: %v", err)
	}
	if err := ForEachMachoSlices(root, visit); err != nil {
		t.Fatalf("ordinary walker behavior changed: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"short table", func(data []byte) []byte { return data[:47] }},
		{"excess slices", func(data []byte) []byte { binary.BigEndian.PutUint32(data[4:], 65); return data }},
		{"member past EOF", func(data []byte) []byte { binary.BigEndian.PutUint32(data[40:], 33); return data }},
		{"overlap", func(data []byte) []byte { binary.BigEndian.PutUint32(data[36:], 128); return data }},
		{"misaligned member", func(data []byte) []byte { binary.BigEndian.PutUint32(data[44:], 8); return data }},
		{"duplicate architecture", func(data []byte) []byte { copy(data[28:36], data[8:16]); return data }},
		{"unknown architecture", func(data []byte) []byte { binary.BigEndian.PutUint32(data[28:], uint32(types.CPUAmd64)); return data }},
		{"bad MTLB magic", func(data []byte) []byte { data[48] = 'X'; return data }},
		{"bad MTLB size", func(data []byte) []byte { binary.LittleEndian.PutUint64(data[64:], 87); return data }},
		{"bad MTLB section", func(data []byte) []byte { binary.LittleEndian.PutUint64(data[80:], 1); return data }},
		{"bad GPU magic", func(data []byte) []byte { data[144] = 0; return data }},
		{"GPU architecture mismatch", func(data []byte) []byte { binary.LittleEndian.PutUint32(data[152:], 84); return data }},
		{"ordinary Mach-O payload", func(data []byte) []byte {
			binary.LittleEndian.PutUint32(data[156:], uint32(types.MH_EXECUTE))
			return data
		}},
		{"malformed GPU load commands", func(data []byte) []byte {
			binary.LittleEndian.PutUint32(data[160:], 1)
			binary.LittleEndian.PutUint32(data[164:], 8)
			return data
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(file, tc.mutate(slices.Clone(data)), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := ForEachMachoSlicesStrict(root, visit); err == nil || errors.Is(err, unwantedVisit) {
				t.Fatalf("malformed/non-Metal universal was not rejected by parsing: %v", err)
			}
		})
	}
}

func TestForEachMachoSlicesStrictFailures(t *testing.T) {
	visit := func(string, []*macho.File) error { return errors.New("unexpected Mach-O") }
	missing := filepath.Join(t.TempDir(), "missing")
	if err := ForEachMachoSlices(missing, visit); err != nil {
		t.Fatalf("legacy missing-root behavior changed: %v", err)
	}
	if err := ForEachMachoSlicesStrict(missing, visit); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("walk failure suppressed: %v", err)
	}
	if err := withMachoSlicesStrict(t.TempDir(), func([]*macho.File) error { return nil }); err == nil {
		t.Fatal("directory read failure suppressed")
	}
	for _, magic := range []string{"\xcf\xfa\xed\xfe", "\xca\xfe\xba\xbe"} {
		root := t.TempDir()
		mustWrite(t, filepath.Join(root, "broken"), magic)
		if err := ForEachMachoSlices(root, visit); err != nil {
			t.Fatalf("legacy recognized-format behavior changed: %v", err)
		}
		if err := ForEachMachoSlicesStrict(root, visit); err == nil {
			t.Fatal("recognized Mach-O parse failure suppressed")
		}
	}
}

func TestForEachMachoSlicesStrictSelectionAndHandler(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "real", "tool")
	arches := []testutil.MachoArch{
		{CPU: types.CPUArm64, SubCPU: types.CPUSubtypeArm64E},
		{CPU: types.CPUAmd64, SubCPU: types.CPUSubtypeX8664All},
	}
	testutil.WriteMacho(t, file, arches...)
	mustWrite(t, filepath.Join(root, "empty"), "")
	mustWrite(t, filepath.Join(root, "short"), "abc")
	if err := os.Symlink("/real", filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/absent", filepath.Join(root, "dangling")); err != nil {
		t.Fatal(err)
	}
	calls := 0
	if err := ForEachMachoSlicesStrict(root, func(path string, slices []*macho.File) error {
		calls++
		if path != file || len(slices) != 2 || slices[1].CPU != types.CPUAmd64 {
			t.Fatalf("unexpected FAT selection: path=%s slices=%v", path, slices)
		}
		return nil
	}); err != nil || calls != 1 {
		t.Fatalf("strict scan calls=%d err=%v", calls, err)
	}
	thin := filepath.Join(t.TempDir(), "thin")
	testutil.WriteMacho(t, thin, arches[0])
	wantErr := errors.New("handler failed")
	if err := withMachoSlicesStrict(thin, func([]*macho.File) error {
		return wantErr
	}); !errors.Is(err, wantErr) {
		t.Fatalf("handler failure suppressed: %v", err)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestWalkFilesInMount checks the shared walker: regular files (incl. nested),
// directory symlinks followed inside the mount, file symlinks skipped, no
// duplicates, and symlinks escaping the mount skipped.
func TestWalkFilesInMount(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	mustWrite(t, filepath.Join(root, "a.txt"), "a")
	mustWrite(t, filepath.Join(root, "sub", "b.txt"), "b")
	mustWrite(t, filepath.Join(root, "real", "inside.txt"), "inside")
	mustWrite(t, filepath.Join(outside, "c.txt"), "c")
	mustWrite(t, filepath.Join(outside, "nested.txt"), "nested")
	if err := os.Symlink(outside, filepath.Join(root, "linkdir")); err != nil {
		t.Fatalf("symlink dir: %v", err)
	}
	if err := os.Symlink("/real", filepath.Join(root, "absdir")); err != nil {
		t.Fatalf("absolute symlink dir: %v", err)
	}
	if err := os.Symlink(filepath.Join(root, "a.txt"), filepath.Join(root, "filelink")); err != nil {
		t.Fatalf("symlink file: %v", err)
	}
	if err := os.Symlink(filepath.Join(outside, "nested.txt"), filepath.Join(root, "real", "nestedlink")); err != nil {
		t.Fatalf("nested symlink file: %v", err)
	}

	var got []string
	if err := walkFilesInMount(root, func(p string) error {
		got = append(got, filepath.Base(p))
		return nil
	}); err != nil {
		t.Fatalf("walkFilesInMount: %v", err)
	}
	slices.Sort(got)
	// file symlink skipped; outside dir symlink skipped; absolute dir symlink
	// rebased into root and deduped against the real path.
	if want := []string{"a.txt", "b.txt", "inside.txt"}; !slices.Equal(got, want) {
		t.Errorf("walked basenames = %v, want %v", got, want)
	}
}

func TestWalkFilesInRootFromFollowsNestedSymlinkDirs(t *testing.T) {
	root := t.TempDir()
	start := filepath.Join(root, "start")
	mustWrite(t, filepath.Join(start, "plain.txt"), "plain")
	mustWrite(t, filepath.Join(root, "target2", "only.txt"), "only")
	if err := os.MkdirAll(filepath.Join(root, "target1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/target1", filepath.Join(start, "link1")); err != nil {
		t.Fatalf("symlink link1: %v", err)
	}
	if err := os.Symlink("/target2", filepath.Join(root, "target1", "link2")); err != nil {
		t.Fatalf("symlink link2: %v", err)
	}
	if err := os.Symlink("/start", filepath.Join(start, "self")); err != nil {
		t.Fatalf("symlink self: %v", err)
	}

	var got []string
	if err := WalkFilesInRootFrom(root, start, func(path string) error {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, filepath.ToSlash(rel))
		return nil
	}); err != nil {
		t.Fatalf("WalkFilesInRootFrom: %v", err)
	}
	slices.Sort(got)
	want := []string{"start/plain.txt", "target2/only.txt"}
	if !slices.Equal(got, want) {
		t.Errorf("walked paths = %v, want %v", got, want)
	}
}

// TestHandleFileInMount checks mount-relative key trimming, the dmg label, and
// the directory filter.
func TestHandleFileInMount(t *testing.T) {
	var gotDmg, gotPath string
	if err := handleFileInMount("/mnt", "", "SystemOS", "/mnt/usr/lib/foo", func(dmg, path string) error {
		gotDmg, gotPath = dmg, path
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if gotDmg != "SystemOS" || gotPath != "/usr/lib/foo" {
		t.Errorf("got (%q,%q), want (SystemOS,/usr/lib/foo)", gotDmg, gotPath)
	}

	called := false
	if err := handleFileInMount("/mnt", "/usr/lib", "X", "/mnt/etc/bar", func(string, string) error {
		called = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("directory filter should have excluded /mnt/etc/bar")
	}
}

// TestForEachMachoInMountMultiEmptyRoot guards the trivial path: a mount
// with no Mach-Os must still return cleanly without surfacing per-task
// errors from the handlers (which never run).
func TestForEachMachoInMountMultiEmptyRoot(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "not-a-macho.txt"), "plain text")

	called := false
	handlers := []NamedMachoScanHandler{{
		Task: "ents",
		Handle: func(path string, m *macho.File) error {
			called = true
			return errors.New("should not run")
		},
	}}
	if err := ForEachMachoInMountMulti(root, handlers); err != nil {
		t.Fatalf("ForEachMachoInMountMulti() error = %v", err)
	}
	if called {
		t.Error("handler ran for a non-Mach-O file")
	}
}

// TestForEachMachoInMountMultiNoHandlers exercises the early-exit when no
// handlers are registered so the walker is never invoked at all.
func TestForEachMachoInMountMultiNoHandlers(t *testing.T) {
	if err := ForEachMachoInMountMulti("/does/not/exist", nil); err != nil {
		t.Fatalf("ForEachMachoInMountMulti(nil) error = %v", err)
	}
}

// TestForEachMachoInMountMultiPerTaskErrorIsolation drives the dispatch
// loop directly so we can verify per-task disable bookkeeping and the
// joined error format without paying for real Mach-O fixtures.
func TestForEachMachoInMountMultiPerTaskErrorIsolation(t *testing.T) {
	// Build the per-task state recordings by hand: we synthesize two
	// (path, *macho.File) deliveries by re-invoking the dispatch
	// closure twice. *macho.File can be nil in tests because the
	// recording handlers below never dereference it.
	type call struct {
		path string
	}
	var entsCalls, machosCalls []call
	entsErr := errors.New("ents boom")
	handlers := []NamedMachoScanHandler{
		{Task: "ents", Handle: func(p string, _ *macho.File) error {
			entsCalls = append(entsCalls, call{p})
			if p == "/bin/a" {
				return entsErr
			}
			return nil
		}},
		{Task: "machos", Handle: func(p string, _ *macho.File) error {
			machosCalls = append(machosCalls, call{p})
			return nil
		}},
	}

	disabled := make([]bool, len(handlers))
	taskErrs := make(map[string]error, len(handlers))
	order := make([]string, 0, len(handlers))
	dispatch := func(path string, m *macho.File) {
		for i := range handlers {
			if disabled[i] || handlers[i].Handle == nil {
				continue
			}
			if err := handlers[i].Handle(path, m); err != nil {
				name := handlers[i].Task
				if _, ok := taskErrs[name]; !ok {
					order = append(order, name)
				}
				taskErrs[name] = err
				disabled[i] = true
			}
		}
	}

	dispatch("/bin/a", nil) // ents fails here
	dispatch("/bin/b", nil) // ents is disabled; machos still runs

	if got, want := entsCalls, []call{{"/bin/a"}}; !slices.Equal(got, want) {
		t.Errorf("ents calls = %v, want %v", got, want)
	}
	if got, want := machosCalls, []call{{"/bin/a"}, {"/bin/b"}}; !slices.Equal(got, want) {
		t.Errorf("machos calls = %v, want %v", got, want)
	}
	if got := taskErrs["ents"]; got != entsErr {
		t.Errorf("taskErrs[ents] = %v, want %v", got, entsErr)
	}
	if _, ok := taskErrs["machos"]; ok {
		t.Errorf("machos recorded an error: %v", taskErrs["machos"])
	}
	if got, want := order, []string{"ents"}; !slices.Equal(got, want) {
		t.Errorf("error order = %v, want %v", got, want)
	}
}

// TestHandlePlistInMount checks the .plist filter and the directory-relative key.
func TestHandlePlistInMount(t *testing.T) {
	root := t.TempDir()
	dir := "/System/Library/FeatureFlags"
	plist := filepath.Join(root, dir, "Foo.plist")
	mustWrite(t, plist, "<plist/>")

	var gotKey, gotData string
	if err := handlePlistInMount(root, dir, plist, func(k, d string) error {
		gotKey, gotData = k, d
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if gotKey != "Foo.plist" || gotData != "<plist/>" {
		t.Errorf("got (%q,%q), want (Foo.plist,<plist/>)", gotKey, gotData)
	}

	called := false
	if err := handlePlistInMount(root, dir, filepath.Join(root, dir, "ignore.txt"), func(string, string) error {
		called = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("non-.plist file should be skipped")
	}
}
