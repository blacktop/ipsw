package macho

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"hash/crc32"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/testutil"
)

type ipaTestEntry struct {
	name string
	data []byte
	mode fs.FileMode
	size uint64
}

func writeTestIPA(t *testing.T, entries ...ipaTestEntry) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Deflate}
		if entry.mode != 0 {
			header.SetMode(entry.mode)
		}
		if entry.size != 0 {
			header.Method = zip.Store
			header.UncompressedSize64 = entry.size
			header.CompressedSize64 = uint64(len(entry.data))
			header.CRC32 = crc32.ChecksumIEEE(entry.data)
		}
		create := zw.CreateHeader
		if entry.size != 0 {
			create = zw.CreateRaw
		}
		w, err := create(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(t.TempDir(), "repacked.ipa")
	if err := os.WriteFile(name, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return name
}

func TestOpenIPAMachO(t *testing.T) {
	for _, tc := range []struct {
		name, arch string
		format     int
		arches     []testutil.MachoArch
	}{
		{"thin XML", "", plist.XMLFormat, []testutil.MachoArch{{CPU: types.CPUArm64}}},
		{"universal binary plist", "arm64e", plist.BinaryFormat, []testutil.MachoArch{{CPU: types.CPUAmd64, SubCPU: 3}, {CPU: types.CPUArm64, SubCPU: 2}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			executable := filepath.Join(t.TempDir(), "standalone.ipa")
			testutil.WriteMacho(t, executable, tc.arches...)
			raw, err := OpenMachO(executable, tc.arch)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			data, err := os.ReadFile(executable)
			if err != nil {
				t.Fatal(err)
			}
			info, err := plist.Marshal(map[string]string{"CFBundleExecutable": "Main"}, tc.format)
			if err != nil {
				t.Fatal(err)
			}
			ipa := writeTestIPA(t,
				ipaTestEntry{name: "Payload/Test-App.app/Watch/Watch.app/Info.plist", data: info},
				ipaTestEntry{name: "Payload/Test-App.app/Info.plist", data: info},
				ipaTestEntry{name: "Payload/Test-App.app/Main", data: data},
			)
			if mr, err := OpenMachO(ipa, tc.arch); err == nil {
				defer mr.Close()
				t.Fatal("raw Mach-O opener accepted an archive; path-based consumers would read ZIP bytes")
			}
			mr, err := OpenIPAMachO(ipa, tc.arch)
			if err != nil {
				t.Fatal(err)
			}
			defer mr.Close()
			if mr.sourceDigest != sha256.Sum256(data) {
				t.Fatal("IPA source digest does not identify the executable")
			}
			if err := os.Remove(ipa); err != nil {
				t.Fatal(err)
			}
			if _, err := mr.SymbolSource(ipa); err != nil {
				t.Fatalf("symbol source reread the IPA: %v", err)
			}
			if mr.File.CPU != types.CPUArm64 || (mr.FatFile != nil) != (len(tc.arches) > 1) {
				t.Fatalf("unexpected Mach-O: CPU=%v, fat=%v", mr.File.CPU, mr.FatFile != nil)
			}
			var magic [4]byte
			if _, err := mr.File.ReadAt(magic[:], 0); err != nil || binary.LittleEndian.Uint32(magic[:]) != uint32(types.Magic64) {
				t.Fatalf("Mach-O backing data unavailable: %x, %v", magic, err)
			}
			tmp := mr.temporaryPath
			if err := mr.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(tmp); !os.IsNotExist(err) {
				t.Fatalf("temporary executable was not removed: %v", err)
			}
		})
	}
}

func TestOpenIPAMachOErrors(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	info := ipaTestEntry{name: "Payload/Test.app/Info.plist", data: []byte(`<plist version="1.0"><dict><key>CFBundleExecutable</key><string>Main</string></dict></plist>`)}
	executable := ipaTestEntry{name: "Payload/Test.app/Main", data: []byte("not a Mach-O")}
	for _, tc := range []struct {
		name, want string
		entries    []ipaTestEntry
	}{
		{"no app", "does not contain", []ipaTestEntry{executable}},
		{"multiple apps", "multiple top-level", []ipaTestEntry{info, {name: "Payload/Other.app/Info.plist", data: info.data}}},
		{"duplicate plist", "multiple top-level", []ipaTestEntry{info, info}},
		{"invalid plist", "failed to parse", []ipaTestEntry{{name: info.name, data: []byte("bad plist")}}},
		{"missing executable name", "invalid CFBundleExecutable", []ipaTestEntry{{name: info.name, data: []byte(`<plist version="1.0"><dict/></plist>`)}}},
		{"traversal", "invalid CFBundleExecutable", []ipaTestEntry{{name: info.name, data: []byte(`<plist version="1.0"><dict><key>CFBundleExecutable</key><string>../Other.app/Main</string></dict></plist>`)}}},
		{"missing executable", "not found", []ipaTestEntry{info}},
		{"duplicate executable", "duplicate executable", []ipaTestEntry{info, executable, executable}},
		{"symlink executable", "regular file", []ipaTestEntry{info, {name: executable.name, data: []byte("../../Main"), mode: fs.ModeSymlink | 0o777}}},
		{"oversized plist", "at most", []ipaTestEntry{{name: info.name, size: maxIPAInfoSize + 1}}},
		{"oversized executable", "at most", []ipaTestEntry{info, {name: executable.name, size: uint64(maxIPAExecutableSize) + 1}}},
		{"invalid Mach-O", "failed to open IPA executable", []ipaTestEntry{info, executable}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mr, err := OpenIPAMachO(writeTestIPA(t, tc.entries...), "")
			if mr != nil {
				defer mr.Close()
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if matches, err := filepath.Glob(filepath.Join(tmp, "ipsw-ipa-*")); err != nil || len(matches) != 0 {
				t.Fatalf("temporary executables remain: %v, %v", matches, err)
			}
		})
	}
}
