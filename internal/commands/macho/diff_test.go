package macho

import (
	"bytes"
	"encoding/binary"
	"slices"
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

// syntheticMachO returns a 64-bit arm64 Mach-O of type typ whose load commands
// are an empty __TEXT segment, an LC_UUID of id, and an LC_UNIXTHREAD, whose
// go-macho LoadSize (8) is shorter than the command (288 bytes).
func syntheticMachO(t *testing.T, typ types.HeaderFileType, id byte) []byte {
	t.Helper()
	text := types.Segment64{LoadCmd: types.LC_SEGMENT_64, Len: 72, Addr: 0x100000000, Memsz: 0x1000, Filesz: 0x1000}
	copy(text.Name[:], "__TEXT")
	uuid := types.UUIDCmd{LoadCmd: types.LC_UUID, Len: 24, UUID: types.UUID{id}}
	const armThreadState64, stateWords = 6, 68
	thread := []uint32{uint32(types.LC_UNIXTHREAD), 16 + 4*stateWords, armThreadState64, stateWords}
	thread = append(thread, make([]uint32, stateWords)...)
	var buf bytes.Buffer
	for _, v := range []any{
		types.FileHeader{Magic: types.Magic64, CPU: types.CPUArm64, Type: typ, NCommands: 3, SizeCommands: 72 + 24 + 4*uint32(len(thread))},
		text,
		uuid,
		thread,
	} {
		if err := binary.Write(&buf, binary.LittleEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

// syntheticFileset returns an MH_FILESET container holding member at
// memberOff under entryID.
func syntheticFileset(t *testing.T, entryID string, member []byte, memberOff int) []byte {
	t.Helper()
	name := append([]byte(entryID), 0)
	for len(name)%8 != 0 {
		name = append(name, 0)
	}
	entry := types.FilesetEntryCmd{
		LoadCmd:       types.LC_FILESET_ENTRY,
		Len:           uint32(32 + len(name)),
		Addr:          0xfffffe0007004000,
		FileOffset:    uint64(memberOff),
		EntryIdOffset: 32,
	}
	var buf bytes.Buffer
	for _, v := range []any{
		types.FileHeader{Magic: types.Magic64, CPU: types.CPUArm64, Type: types.MH_FILESET, NCommands: 1, SizeCommands: entry.Len},
		entry,
		name,
	} {
		if err := binary.Write(&buf, binary.LittleEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	data := make([]byte, memberOff, memberOff+len(member))
	copy(data, buf.Bytes())
	return append(data, member...)
}

// TestLoadCommandsRegionMatchesStandaloneBytes pins that rebuilding the region
// leaves standalone hashes unchanged: it must equal the on-disk bytes.
func TestLoadCommandsRegionMatchesStandaloneBytes(t *testing.T) {
	m := openSelfT(t)
	region, hdrSize := loadCommandsRegion(m)
	if region == nil {
		t.Fatal("could not rebuild the test binary's load commands")
	}
	disk := make([]byte, hdrSize+int(m.SizeCommands))
	if _, err := m.ReadAt(disk, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(region, disk) {
		t.Fatal("rebuilt header and load commands differ from the file's bytes")
	}
}

func TestLoadCommandsHashUsesTheImagesOwnHeader(t *testing.T) {
	const entryID = "com.example.member"
	member := syntheticMachO(t, types.MH_KEXT_BUNDLE, 1)
	standalone, err := macho.NewFile(bytes.NewReader(member))
	if err != nil {
		t.Fatal(err)
	}
	want := loadCommandsHash(standalone, &DiffConfig{})
	if want == "" {
		t.Fatal("standalone Mach-O produced no load-command hash")
	}

	t.Run("fileset member at a nonzero offset", func(t *testing.T) {
		container, err := macho.NewFile(bytes.NewReader(syntheticFileset(t, entryID, member, 0x1000)))
		if err != nil {
			t.Fatal(err)
		}
		m, err := container.GetFileSetFileByName(entryID)
		if err != nil {
			t.Fatal(err)
		}
		if got := loadCommandsHash(m, &DiffConfig{}); got != want {
			t.Fatalf("member hash = %q, want the standalone hash %q", got, want)
		}
	})

	t.Run("cache reader in other coordinates", func(t *testing.T) {
		// A dyld_shared_cache image's CacheReader addresses the subcache
		// holding its __LINKEDIT; offset 0 there is not the image's header.
		other := bytes.NewReader(syntheticMachO(t, types.MH_DYLIB, 2))
		m, err := macho.NewFile(bytes.NewReader(member), macho.FileConfig{
			CacheReader: types.NewCustomSectionReader(other, &types.VMAddrConverter{}, 0, int64(other.Len())),
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := loadCommandsHash(m, &DiffConfig{}); got != want {
			t.Fatalf("hash = %q, want the standalone hash %q", got, want)
		}
	})
}

// TestLoadCommandsDigestThreadCommandBoundaries walks past an LC_UNIXTHREAD,
// whose go-macho LoadSize (8) is shorter than the command: fields after it must
// still be normalized, and its thread state must still be hashed.
func TestLoadCommandsDigestThreadCommandBoundaries(t *testing.T) {
	const headerSize, segmentSize, uuidSize, threadSize = 32, 72, 24, 288
	hash := func(data []byte, conf *DiffConfig) string {
		t.Helper()
		m, err := macho.NewFile(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		got := loadCommandsHash(m, conf)
		if got == "" {
			t.Fatal("empty load-command hash")
		}
		return got
	}
	original := syntheticMachO(t, types.MH_EXECUTE, 1)
	// Move the thread command ahead of the LC_UUID.
	uuidCmd := original[headerSize+segmentSize : headerSize+segmentSize+uuidSize]
	threadFirst := slices.Concat(original[:headerSize+segmentSize], original[headerSize+segmentSize+uuidSize:], uuidCmd)

	t.Run("UUID after the thread command stays volatile", func(t *testing.T) {
		changed := bytes.Clone(threadFirst)
		changed[headerSize+segmentSize+threadSize+8] ^= 1
		if hash(changed, &DiffConfig{}) != hash(threadFirst, &DiffConfig{}) {
			t.Fatal("a UUID-only change altered the digest")
		}
	})
	t.Run("thread state before the UUID stays structural", func(t *testing.T) {
		changed := bytes.Clone(threadFirst)
		changed[headerSize+segmentSize+16] ^= 1
		if hash(changed, &DiffConfig{}) == hash(threadFirst, &DiffConfig{}) {
			t.Fatal("a thread-state change disappeared from the digest")
		}
	})
	t.Run("filtered digest keeps the thread state", func(t *testing.T) {
		changed := bytes.Clone(original)
		changed[headerSize+segmentSize+uuidSize+16] ^= 1
		conf := &DiffConfig{BlockList: []string{"__LLVM"}}
		if hash(changed, conf) == hash(original, conf) {
			t.Fatal("a thread-state change disappeared from the filtered digest")
		}
	})
}

// symbolNormalizationCases pairs names with what the diff normalizer must
// produce. The expected values are those of the unguarded pipeline.
var symbolNormalizationCases = []struct{ in, want string }{
	{"", ""},
	{"_objc_msgSend", "_objc_msgSend"},
	{"-[NSObject description]", "-[NSObject description]"},
	{"___foo_block_invoke.323", "___foo_block_invoke"},
	{"___foo_block_invoke.870.cold.1", "___foo_block_invoke"},
	{"_bar.cold", "_bar"},
	{"_bar.cold.cold.2", "_bar"},
	{"_bar.cold2", "_bar.cold2"},
	{"_bar.COLD", "_bar.COLD"},
	{"_name2", "_name2"},
	{"_v1.2.3", "_v1"},
	{"OSLog.12.x", "OSLog.12.x"},
	{".1", ""},
	{"..1", "."},
	{"a.", "a."},
	{"ünïcødé.12", "ünïcødé"},
	{"日本.cold", "日本"},
	{"foo.١٢", "foo.١٢"}, // non-ASCII digits
	{"foo.cold\n", "foo.cold\n"},
	{"foo.12\n", "foo.12\n"},
	{"foo.1\x00", "foo.1\x00"},
	{"foo.\xff1", "foo.\xff1"},
	{"/AppleInternal/Library/BuildRoots/0123abc/Sources/x.o.7", "/AppleInternal/Library/BuildRoots/<BUILDROOT>/Sources/x.o"},
}

// unguardedNormalizeSymbolForDiff is the normalizer without the suffix guard.
func unguardedNormalizeSymbolForDiff(value string) string {
	return generatedSymbolCounterRE.ReplaceAllString(normalizeBuildPathForDiff(value), "")
}

func TestNormalizeSymbolForDiffMatchesUnguardedPipeline(t *testing.T) {
	for _, tc := range symbolNormalizationCases {
		if ref := unguardedNormalizeSymbolForDiff(tc.in); ref != tc.want {
			t.Fatalf("case %q expects %q, but the unguarded pipeline gives %q", tc.in, tc.want, ref)
		}
		if got := normalizeSymbolForDiff(tc.in); got != tc.want {
			t.Errorf("normalizeSymbolForDiff(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func FuzzNormalizeSymbolForDiffMatchesUnguardedPipeline(f *testing.F) {
	for _, tc := range symbolNormalizationCases {
		f.Add(tc.in)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if got, want := normalizeSymbolForDiff(value), unguardedNormalizeSymbolForDiff(value); got != want {
			t.Fatalf("normalizeSymbolForDiff(%q) = %q, want %q", value, got, want)
		}
	})
}
