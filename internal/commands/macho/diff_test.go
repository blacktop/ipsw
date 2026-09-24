package macho

import (
	"bytes"
	"encoding/binary"
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
