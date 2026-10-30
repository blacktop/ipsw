package macho

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	gomacho "github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

func swiftSectionFixture(t *testing.T, name string, payload []byte) *gomacho.File {
	t.Helper()
	sections := []types.Section{{
		Seg: "__TEXT", Name: "__swift5_reflstr", Addr: 0x1300, Offset: 0x300, Size: 1}}
	if name != "" {
		sections = append(sections, types.Section{
			Seg: "__TEXT", Name: name, Addr: 0x1320, Offset: 0x320, Size: uint64(len(payload))})
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
