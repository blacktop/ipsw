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

// BenchmarkDiffInfoEquivalentDSC measures the common unchanged DSC-image path.
// Identical sorted inputs should return without normalization allocations.
func BenchmarkDiffInfoEquivalentDSC(b *testing.B) {
	m := openSelf(b)
	conf := &DiffConfig{
		CStrings:           true,
		FuncStarts:         true,
		IgnoreLoadCommands: true,
	}
	info := GenerateContainerDiffInfo(m, conf)
	b.ReportAllocs()
	for b.Loop() {
		if !info.Equivalent(*info, conf) {
			b.Fatal("identical DiffInfo is not equivalent")
		}
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
	want := loadCommandsDigest(dup(), hdrSize, m.Loads, m.Sections, &DiffConfig{})
	if loadCommandsDigest(dup(), hdrSize, m.Loads, m.Sections, &DiffConfig{}) != want {
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
	if got := loadCommandsDigest(meta, hdrSize, m.Loads, m.Sections, &DiffConfig{}); got != want {
		t.Fatalf("digest changed on a build-metadata-only mutation:\n want %s\n  got %s", want, got)
	}

	// A structural byte (the first load command's cmd field, in the 8-byte
	// header that is never zeroed) must change the digest.
	structural := dup()
	structural[hdrSize] ^= 0xFF
	if got := loadCommandsDigest(structural, hdrSize, m.Loads, m.Sections, &DiffConfig{}); got == want {
		t.Fatal("digest unchanged on a structural mutation; it is over-zeroing")
	}
}

func TestLoadCommandsDigestHonorsSectionFilters(t *testing.T) {
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

	segmentOffset := hdrSize
	segmentIndex := -1
	var segment *macho.Segment
	for idx, load := range m.Loads {
		seg, ok := load.(*macho.Segment)
		if ok && seg.Nsect >= 2 && uint64(seg.Firstsect)+uint64(seg.Nsect) <= uint64(len(m.Sections)) {
			segmentIndex = idx
			segment = seg
			break
		}
		segmentOffset += int(load.LoadSize())
	}
	if segment == nil {
		t.Skip("test binary has no segment with two sections")
	}

	changedBytes := append([]byte(nil), base...)
	changedBytes[segmentOffset+24] ^= 0xff // segment vmaddr
	changedSections := make([]*types.Section, len(m.Sections))
	for idx, section := range m.Sections {
		clone := *section
		changedSections[idx] = &clone
	}
	blockedIndex := int(segment.Firstsect)
	includedIndex := blockedIndex + 1
	changedSections[blockedIndex].Size++
	changedSections[includedIndex].Addr += 4
	changedSections[includedIndex].Offset += 4

	blockList := &DiffConfig{BlockList: []string{m.Sections[blockedIndex].Seg + "." + m.Sections[blockedIndex].Name}}
	want := loadCommandsDigest(append([]byte(nil), base...), hdrSize, m.Loads, m.Sections, blockList)
	if got := loadCommandsDigest(changedBytes, hdrSize, m.Loads, changedSections, blockList); got != want {
		t.Fatalf("blocked section/layout drift changed digest:\n want %s\n  got %s", want, got)
	}
	if got := loadCommandsDigest(append([]byte(nil), changedBytes...), hdrSize, m.Loads, changedSections, &DiffConfig{}); got == loadCommandsDigest(append([]byte(nil), base...), hdrSize, m.Loads, m.Sections, &DiffConfig{}) {
		t.Fatal("unfiltered digest ignored segment layout drift")
	}

	changedLoads := append([]macho.Load(nil), m.Loads...)
	changedSegment := *segment
	changedSegment.Prot ^= 1
	changedLoads[segmentIndex] = &changedSegment
	if got := loadCommandsDigest(append([]byte(nil), base...), hdrSize, changedLoads, m.Sections, blockList); got == want {
		t.Fatal("filtered digest ignored a segment protection change")
	}
}

func filteredSegmentDigest(seg *macho.Segment, sections []*types.Section, conf *DiffConfig) string {
	h := sha256.New()
	writeFilteredSegmentDigest(h, seg, sections, conf)
	return hex.EncodeToString(h.Sum(nil))
}

func TestFilteredSegmentDigestKeepsPageZeroSize(t *testing.T) {
	conf := &DiffConfig{BlockList: []string{"__TEXT.__info_plist"}}
	pageZero := &macho.Segment{SegmentHeader: macho.SegmentHeader{
		LoadCmd: types.LC_SEGMENT_64,
		Name:    "__PAGEZERO",
		Memsz:   0x100000000,
	}}
	want := filteredSegmentDigest(pageZero, nil, conf)
	changed := *pageZero
	changed.Memsz += 0x1000
	if got := filteredSegmentDigest(&changed, nil, conf); got == want {
		t.Fatal("filtered digest ignored __PAGEZERO guard-size change")
	}
}

func TestFilteredSegmentDigestKeepsIncludedSectionReserved1(t *testing.T) {
	conf := &DiffConfig{AllowList: []string{"__TEXT.__stubs"}}
	segment := &macho.Segment{SegmentHeader: macho.SegmentHeader{
		LoadCmd: types.LC_SEGMENT_64,
		Name:    "__TEXT",
		Nsect:   1,
	}}
	section := &types.Section{SectionHeader: types.SectionHeader{
		Name:      "__stubs",
		Seg:       "__TEXT",
		Size:      6,
		Flags:     types.SymbolStubs,
		Reserved1: 4,
		Reserved2: 6,
	}}

	want := filteredSegmentDigest(segment, []*types.Section{section}, conf)
	changed := *section
	changed.Reserved1++
	if got := filteredSegmentDigest(segment, []*types.Section{&changed}, conf); got == want {
		t.Fatal("filtered digest ignored included section reserved1 change")
	}
}

func TestGenerateDiffInfoBlockListExcludesSegmentLayout(t *testing.T) {
	m := openSelfT(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}

	segmentOffset := 28
	if m.Magic == types.Magic64 {
		segmentOffset = 32
	}
	localSection := -1
	var segment *macho.Segment
	for _, load := range m.Loads {
		seg, ok := load.(*macho.Segment)
		if ok && uint64(seg.Firstsect)+uint64(seg.Nsect) <= uint64(len(m.Sections)) {
			for idx := 0; idx+1 < int(seg.Nsect); idx++ {
				first := m.Sections[int(seg.Firstsect)+idx]
				second := m.Sections[int(seg.Firstsect)+idx+1]
				if first.Size > 0 && sectionContainsCode(first) && sectionContainsCode(second) {
					segment = seg
					localSection = idx
					break
				}
			}
		}
		if segment != nil {
			break
		}
		segmentOffset += int(load.LoadSize())
	}
	if segment == nil {
		t.Skip("test binary has no adjacent code sections to patch")
	}

	segmentHeaderSize, sectionHeaderSize := 56, 68
	sectionSizeOffset, sectionAddressOffset, sectionFileOffset := 36, 32, 40
	if segment.Command() == types.LC_SEGMENT_64 {
		segmentHeaderSize, sectionHeaderSize = 72, 80
		sectionSizeOffset, sectionAddressOffset, sectionFileOffset = 40, 32, 48
	}
	blockedHeader := segmentOffset + segmentHeaderSize + localSection*sectionHeaderSize
	includedHeader := blockedHeader + sectionHeaderSize
	if includedHeader+sectionHeaderSize > len(raw) {
		t.Fatal("section headers extend beyond test binary")
	}
	if segment.Command() == types.LC_SEGMENT_64 {
		m.ByteOrder.PutUint64(raw[blockedHeader+sectionSizeOffset:], m.ByteOrder.Uint64(raw[blockedHeader+sectionSizeOffset:])+1)
		m.ByteOrder.PutUint64(raw[includedHeader+sectionAddressOffset:], m.ByteOrder.Uint64(raw[includedHeader+sectionAddressOffset:])+4)
	} else {
		m.ByteOrder.PutUint32(raw[blockedHeader+sectionSizeOffset:], m.ByteOrder.Uint32(raw[blockedHeader+sectionSizeOffset:])+1)
		m.ByteOrder.PutUint32(raw[includedHeader+sectionAddressOffset:], m.ByteOrder.Uint32(raw[includedHeader+sectionAddressOffset:])+4)
	}
	m.ByteOrder.PutUint32(raw[includedHeader+sectionFileOffset:], m.ByteOrder.Uint32(raw[includedHeader+sectionFileOffset:])+4)

	patchedPath := t.TempDir() + "/patched-macho"
	if err := os.WriteFile(patchedPath, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	patched, err := macho.Open(patchedPath)
	if err != nil {
		t.Fatalf("open patched Mach-O: %v", err)
	}
	t.Cleanup(func() { _ = patched.Close() })

	blocked := m.Sections[int(segment.Firstsect)+localSection]
	conf := &DiffConfig{BlockList: []string{blocked.Seg + "." + blocked.Name}}
	oldInfo := GenerateDiffInfo(m, conf)
	newInfo := GenerateDiffInfo(patched, conf)
	if oldInfo.LoadCmdHash != newInfo.LoadCmdHash {
		t.Fatal("blocked section/layout drift changed GenerateDiffInfo LoadCmdHash")
	}
	if !newInfo.Equivalent(*oldInfo, conf) {
		t.Fatal("blocked section/layout drift made GenerateDiffInfo unequal")
	}
}
