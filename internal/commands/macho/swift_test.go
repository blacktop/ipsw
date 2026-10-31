package macho

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gomacho "github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

func swiftSectionFixture(t *testing.T, name string, payload []byte) *gomacho.File {
	t.Helper()
	return swiftSectionDataFixture(t, name, payload, uint64(len(payload)))
}

func swiftSectionDataFixture(t *testing.T, name string, payload []byte, sectionSize uint64) *gomacho.File {
	t.Helper()
	sections := []types.Section{{
		Seg: "__TEXT", Name: "__swift5_reflstr", Addr: 0x1300, Offset: 0x300, Size: 1}}
	if name != "" {
		sections = append(sections, types.Section{
			Seg: "__TEXT", Name: name, Addr: 0x1320, Offset: 0x320, Size: sectionSize})
	}
	data := make([]byte, 0x400)
	segment := gomacho.Segment{
		LoadCmd: types.LC_SEGMENT_64,
		Len:     uint32(binary.Size(types.Segment64{}) + len(sections)*binary.Size(types.Section64{})),
		Name:    "__TEXT", Addr: 0x1000, Memsz: uint64(len(data)), Filesz: uint64(len(data)),
		Nsect: uint32(len(sections))}
	header := types.FileHeader{
		Magic: types.Magic64, CPU: types.CPUArm64, Type: types.MH_DYLIB,
		NCommands: 1, SizeCommands: segment.Len,
	}
	off := header.Put(data, binary.LittleEndian)
	off += segment.Put64(data[off:], binary.LittleEndian)
	for _, section := range sections {
		off += section.Put64(data[off:], binary.LittleEndian)
	}
	copy(data[0x320:], payload)
	m, err := gomacho.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	return m
}

func swiftTypeFixture(t *testing.T, installName, typeName string) *gomacho.File {
	t.Helper()
	payload := make([]byte, 0x80)
	binary.LittleEndian.PutUint32(payload, 0x20)        // __swift5_types -> descriptor
	binary.LittleEndian.PutUint32(payload[0x20:], 17)   // non-generic struct descriptor
	binary.LittleEndian.PutUint32(payload[0x28:], 0x38) // descriptor -> type name
	copy(payload[0x60:], typeName)
	m := swiftSectionDataFixture(t, "__swift5_types", payload, 4)
	m.AddLoad(&gomacho.IDDylib{Dylib: gomacho.Dylib{
		DylibCmd: types.DylibCmd{LoadCmd: types.LC_ID_DYLIB}, Name: installName,
	}})
	return m
}

func TestSwiftPrecacheErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		dump func(*Swift) error
	}{
		{"dump", (*Swift).Dump},
		{"type", func(s *Swift) error { return s.DumpType(".*") }},
		{"protocol", func(s *Swift) error { return s.DumpProtocol(".*") }},
		{"extension", func(s *Swift) error { return s.DumpExtension(".*") }},
		{"associated type", func(s *Swift) error { return s.DumpAssociatedType(".*") }},
		{"headers", (*Swift).WriteHeaders},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := swiftSectionFixture(t, "__constg_swiftt", []byte{1})
			s, err := NewSwift(m, nil, &SwiftConfig{Name: "Synthetic"})
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.dump(s); err == nil || !strings.Contains(err.Error(), "failed to precache swift fields/types") {
				t.Fatalf("expected precache error, got %v", err)
			}
		})
	}
}

func TestSwiftDependencyErrorsDoNotAbort(t *testing.T) {
	for _, tc := range []struct {
		name string
		dump func(*Swift) error
	}{
		{"dump", (*Swift).Dump},
		{"type", func(s *Swift) error { return s.DumpType(".*") }},
		{"protocol", func(s *Swift) error { return s.DumpProtocol(".*") }},
		{"extension", func(s *Swift) error { return s.DumpExtension(".*") }},
		{"associated type", func(s *Swift) error { return s.DumpAssociatedType(".*") }},
		{"headers", (*Swift).WriteHeaders},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Swift{
				conf: &SwiftConfig{Name: "Primary", Deps: true, Output: t.TempDir()},
				file: swiftSectionFixture(t, "", nil),
				deps: []*gomacho.File{
					swiftSectionFixture(t, "__constg_swiftt", []byte{1}),
					swiftSectionFixture(t, "__constg_swiftt", []byte{1}),
				},
			}
			err := tc.dump(s)
			if err == nil {
				t.Fatal("dependency precache failures were dropped")
			}
			if got := strings.Count(err.Error(), "failed to precache swift fields/types"); got != 2 {
				t.Fatalf("expected both dependency failures, got %d in %v", got, err)
			}
		})
	}
}

func TestSwiftHeadersKeepImageDestinations(t *testing.T) {
	output := t.TempDir()
	primary := swiftTypeFixture(t, "/System/Library/Frameworks/Primary.framework/Primary", "Record")
	s, err := NewSwift(primary, nil, &SwiftConfig{Name: "Primary", Output: output})
	if err != nil {
		t.Fatal(err)
	}
	s.conf.Deps = true
	s.deps = []*gomacho.File{
		swiftTypeFixture(t, "/System/Library/Frameworks/Dependency.framework/Dependency", "Record"),
		swiftTypeFixture(t, "/System/Library/PrivateFrameworks/Primary.framework/Primary", "Other"),
		swiftTypeFixture(t, "/usr/lib/dependency", "Third"),
	}
	if err := s.WriteHeaders(); err != nil {
		t.Fatal(err)
	}
	for _, image := range []struct{ folder, typeName string }{
		{"Primary", "Record"},
		{"Dependency", "Record"},
		{"Primary-2", "Other"},
		{"dependency-2", "Third"},
	} {
		t.Run(image.folder, func(t *testing.T) {
			dir := filepath.Join(output, image.folder)
			body, err := os.ReadFile(filepath.Join(dir, image.typeName+".swift"))
			if err != nil || !strings.Contains(string(body), "struct "+image.typeName) {
				t.Fatalf("type header = %q, %v", body, err)
			}
			umbrella, err := os.ReadFile(filepath.Join(dir, image.folder+".swift"))
			if err != nil || !strings.Contains(string(umbrella), "import \""+image.typeName+".swift\"") ||
				strings.Count(string(umbrella), "import \"") != 1 {
				t.Fatalf("umbrella header = %q, %v", umbrella, err)
			}
		})
	}
	if s.conf.Name != "Primary" {
		t.Fatalf("header export changed the configured name to %q", s.conf.Name)
	}
}

func TestSwiftDumpSectionErrors(t *testing.T) {
	for _, tc := range []struct {
		section string
		payload []byte
		all     bool
		want    string
	}{
		{"__swift5_types", []byte{0, 0x20, 0, 0}, false, "swift types"},
		{"__swift5_protos", []byte{0, 0x20, 0, 0}, false, "swift protocols"},
		{"__swift5_proto", []byte{0, 0x20, 0, 0}, false, "swift protocol conformances"},
		{"__swift5_assocty", []byte{1}, false, "swift associated types"},
		{"__swift5_entry", []byte{1}, true, "swift entrypoint"},
		{"__swift5_builtin", []byte{1}, true, "swift built-in types"},
		{"__swift5_mpenum", []byte{1}, true, "swift multi-payload enums"},
		{"__swift5_capture", []byte{1}, true, "swift closures"},
		{"__swift5_replace", []byte{1}, true, "swift dynamic replacement info"},
		{"__swift5_replac2", []byte{1}, true, "swift dynamic replacement info opaque types"},
		{"__swift5_acfuncs", []byte{1}, true, "swift accessible functions"},
	} {
		t.Run(tc.section, func(t *testing.T) {
			s, err := NewSwift(swiftSectionFixture(t, tc.section, tc.payload), nil, &SwiftConfig{All: tc.all})
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Dump(); err == nil || !strings.Contains(err.Error(), "failed to parse "+tc.want) {
				t.Fatalf("expected %s error, got %v", tc.want, err)
			}
		})
	}
}

func TestSwiftDumpMissingSections(t *testing.T) {
	s, err := NewSwift(swiftSectionFixture(t, "", nil), nil, &SwiftConfig{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Dump(); err != nil {
		t.Fatalf("absent optional sections: %v", err)
	}
}
