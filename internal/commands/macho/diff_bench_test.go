package macho

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
)

// openSelf opens the test binary itself as a real arm64 Mach-O so the
// benchmarks exercise representative load commands, sections, cstrings, and
// function starts without needing IPSW fixtures.
func openSelf(b *testing.B) *macho.File {
	b.Helper()
	exe, err := os.Executable()
	if err != nil {
		b.Fatal(err)
	}
	m, err := macho.Open(exe)
	if err != nil {
		b.Skipf("test binary is not a plain Mach-O here: %v", err)
	}
	b.Cleanup(func() { m.Close() })
	return m
}

// openSelfT is the *testing.T twin of openSelf for non-benchmark tests.
func openSelfT(t *testing.T) *macho.File {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	m, err := macho.Open(exe)
	if err != nil {
		t.Skipf("test binary is not a plain Mach-O here: %v", err)
	}
	t.Cleanup(func() { m.Close() })
	return m
}

// BenchmarkGenerateDiffInfo measures the per-binary scan cost on the cold
// path: every Mach-O in every volume goes through this once per side.
func BenchmarkGenerateDiffInfo(b *testing.B) {
	m := openSelf(b)
	conf := &DiffConfig{Markdown: true, DiffTool: "git"}
	b.ReportAllocs()
	for b.Loop() {
		_ = GenerateDiffInfo(m, conf)
	}
}

// BenchmarkGenerateDiffInfoStrsStarts is the same scan with the heavy flags
// the canonical CI invocation passes (--strs --starts).
func BenchmarkGenerateDiffInfoStrsStarts(b *testing.B) {
	m := openSelf(b)
	conf := &DiffConfig{Markdown: true, DiffTool: "git", CStrings: true, FuncStarts: true}
	b.ReportAllocs()
	for b.Loop() {
		_ = GenerateDiffInfo(m, conf)
	}
}

// BenchmarkDiffInfoGobRoundTrip measures the temp-dir gob write+read that the
// machos job performs once per old-side binary (write) and once per matched
// new-side binary (read).
func BenchmarkDiffInfoGobRoundTrip(b *testing.B) {
	m := openSelf(b)
	conf := &DiffConfig{Markdown: true, DiffTool: "git", CStrings: true, FuncStarts: true}
	info := GenerateDiffInfo(m, conf)
	dir := b.TempDir()
	b.ReportAllocs()
	for b.Loop() {
		if err := WriteCachedDiffInfo(dir, "bench", info); err != nil {
			b.Fatal(err)
		}
		if _, err := ReadCachedDiffInfo(dir, "bench"); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkIsMachO measures the per-file magic sniff the shared Mach-O walk
// performs on EVERY file in EVERY volume (the overwhelmingly common case is
// a non-Mach-O file).
func BenchmarkIsMachO(b *testing.B) {
	notMacho := b.TempDir() + "/plain.txt"
	if err := os.WriteFile(notMacho, []byte("just text, definitely not a binary"), 0o644); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = magic.IsMachO(notMacho)
	}
}

// BenchmarkGitDiffSubprocess measures one host-git unified-diff render: the
// cold path spawns one per UPDATED binary (FormatUpdatedDiff -> utils.GitDiff
// with DiffTool "git"), so thousands of changed binaries mean thousands of
// process spawns.
func BenchmarkGitDiffSubprocess(b *testing.B) {
	m := openSelf(b)
	conf := &DiffConfig{Markdown: true, DiffTool: "git", CStrings: true, FuncStarts: true}
	info := GenerateDiffInfo(m, conf)
	src := info.String()
	// Mutate a few lines so git produces a real hunk, like a version bump does.
	dst := src + "extra: line-added-by-update\n"
	b.ReportAllocs()
	for b.Loop() {
		if _, err := utils.GitDiff(src+"\n", dst+"\n", &utils.GitDiffConfig{Tool: "git"}); err != nil {
			b.Fatal(err)
		}
	}
}

// TestFunctionHashesMatchPerFunctionRead pins the section-batched function
// hashing against the original per-function GetFunctionData path: every
// function's digest must be byte-identical, since --starts change detection
// keys on these hashes.
func TestFunctionHashesMatchPerFunctionRead(t *testing.T) {
	m := openSelfT(t)
	conf := &DiffConfig{FuncStarts: true}
	funcs := m.GetFunctions()
	if len(funcs) == 0 {
		t.Skip("test binary has no LC_FUNCTION_STARTS")
	}

	got := functionContentHashes(m, funcs, conf)

	// Reference: the old behavior — read each function directly and hash.
	want := make(map[uint64]string, len(funcs))
	for _, fn := range funcs {
		sec := m.FindSectionForVMAddr(fn.StartAddr)
		if sec != nil && !sectionIncluded(sec.Seg+"."+sec.Name, conf) {
			continue
		}
		data, err := m.GetFunctionData(fn)
		if err != nil || len(data) == 0 {
			continue
		}
		sum := sha256.Sum256(data)
		want[fn.StartAddr] = hex.EncodeToString(sum[:])
	}

	if len(got) != len(want) {
		t.Fatalf("hash count mismatch: batched=%d per-function=%d", len(got), len(want))
	}
	for addr, w := range want {
		if got[addr] != w {
			t.Fatalf("function %#x hash mismatch: batched=%s per-function=%s", addr, got[addr], w)
		}
	}
}

// TestLoadCommandsDigestIgnoresBuildMetadata pins the precision fix: the
// load-commands digest must NOT change when only volatile build-metadata /
// linkedit bytes change (which a point-release rebuild bumps on every binary),
// but MUST change when a structural byte (kept in the hash) changes.
func TestLoadCommandsDigestIgnoresBuildMetadata(t *testing.T) {
	m := openSelfT(t)
	hdrSize := 28
	if m.Magic == types.Magic64 {
		hdrSize = 32
	}
	region := hdrSize + int(m.SizeCommands)
	base := make([]byte, region)
	if n, err := m.ReadAt(base, 0); err != nil || n != region {
		t.Fatalf("read region: n=%d err=%v", n, err)
	}

	dup := func() []byte { b := make([]byte, len(base)); copy(b, base); return b }
	want := loadCommandsDigest(dup(), hdrSize, m.Loads)
	if loadCommandsDigest(dup(), hdrSize, m.Loads) != want {
		t.Fatal("digest is not stable across identical input")
	}

	// Scribble 0xFF over every volatile range: the digest must be unchanged,
	// because those bytes are zeroed before hashing regardless of content.
	meta := dup()
	off := hdrSize
	touchedVolatile := false
	for _, l := range m.Loads {
		sz := int(l.LoadSize())
		if sz <= 0 || off+sz > len(meta) {
			break
		}
		for _, r := range volatileLoadCmdRanges(l.Command(), sz) {
			start, end := off+r[0], off+r[1]
			if start < off+8 {
				start = off + 8
			}
			if end > off+sz {
				end = off + sz
			}
			for i := start; i < end; i++ {
				meta[i] = 0xFF
				touchedVolatile = true
			}
		}
		off += sz
	}
	if !touchedVolatile {
		t.Skip("test binary has no volatile load-command fields to exercise")
	}
	if got := loadCommandsDigest(meta, hdrSize, m.Loads); got != want {
		t.Fatalf("digest changed on a build-metadata-only mutation:\n want %s\n  got %s", want, got)
	}

	// A structural byte (the first load command's cmd field, in the 8-byte
	// header that is never zeroed) must change the digest.
	structural := dup()
	structural[hdrSize] ^= 0xFF
	if got := loadCommandsDigest(structural, hdrSize, m.Loads); got == want {
		t.Fatal("digest unchanged on a structural mutation; it is over-zeroing")
	}
}
