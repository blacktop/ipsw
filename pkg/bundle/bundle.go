package bundle

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/pkg/devicetree"
)

const Magic = "BUND"

type Header struct {
	Unknown1 uint16  // 0x0200
	Unknown2 uint16  // 0x1400
	_        uint32  // padding ?
	Magic    [4]byte // "BUND"
	_        uint16  // padding ?
	Type     uint16  // 3 (AOP/DCP), 4 (ExclaveCore)
}

type Bundle struct {
	Header
	TypeHeader any
	Config     Config
	Files      []File
}

func (b Bundle) String() string {
	s := fmt.Sprintf("Bundle: %s\n", string(b.Magic[:]))
	s += fmt.Sprintf("  Type: %d\n", b.Type)
	switch b.Type {
	case 3:
		s += "  Config:\n"
		s += fmt.Sprintf("    Unk1: %d\n", b.Config.Unk1)
		s += fmt.Sprintf("    Unk2: %d\n", b.Config.Unk2)
		s += "    Assets:\n"
		for i, h := range b.Config.Assets {
			s += fmt.Sprintf("      %3s) %s\n", fmt.Sprintf("%d", i+1), h)
		}
		s += "    TOC:\n"
		for _, t := range b.Config.TOC {
			s += fmt.Sprintf("      %s\n", t)
		}
		s += "Compartments:\n"
		for _, f := range b.Files {
			s += fmt.Sprintf("%s\n", f)
		}
	case 4:
		s += "  Ranges:\n"
		for i, f := range b.TypeHeader.(Type4).Ranges {
			s += fmt.Sprintf("    %3s) %s\n", fmt.Sprintf("%d", i+1), f)
		}
	}
	return s
}

type Segment struct {
	Name   string
	Offset uint64
	Size   uint64
}

type Section struct {
	Name   string
	Offset uint64
	Size   uint64
}

type File struct {
	Name      string
	Type      string
	Segments  []Segment
	Sections  []Section
	Endpoints []Endpoint
}

func (f File) Segment(name string) *Segment {
	for _, seg := range f.Segments {
		if seg.Name == name {
			return &seg
		}
	}
	return nil
}

func (f File) String() string {
	s := fmt.Sprintf("  %s (%s)\n", f.Name, f.Type)
	for _, seg := range f.Segments {
		if seg.Size == 0 {
			continue
		}
		s += fmt.Sprintf("    sz=0x%08x off=0x%08x-0x%08x __%s\n", seg.Size, seg.Offset, seg.Offset+seg.Size, seg.Name)
		for _, sec := range f.Sections {
			if sec.Size == 0 {
				continue
			}
			if strings.HasPrefix(sec.Name, seg.Name) && !strings.EqualFold(sec.Name, seg.Name) {
				s += fmt.Sprintf("      sz=0x%08x off=0x%08x-0x%08x __%s\n", sec.Size, sec.Offset, sec.Offset+sec.Size, sec.Name)
			}
		}
	}
	if len(f.Endpoints) > 0 {
		s += "    endpoints:\n"
		for i, ep := range f.Endpoints {
			s += fmt.Sprintf("      %3s) %s\n", fmt.Sprintf("%d", i+1), ep)
		}
	}
	return s
}

type Type3 struct {
	UUID             types.UUID
	_                [4]uint64 // padding ?
	SubType          uint64
	_                uint64 // padding ?
	FileSz           uint64
	_                uint64 // padding ?
	EndOff           uint64
	DataOff          uint64 // roottask __DATA offset
	_                uint64 // padding ?
	KernelDataOffset uint64 // 2D0C000h
	_                uint64 // padding ?
	TextOff          uint64 // roottask __TEXT offset
	UnkSz            uint64
	TextOffAgain     uint64 // ???
	TextSz           uint64 // is x14000 again
	UnkSzMaybe       uint64 // 2CF8000h
	_                uint64 // padding ?
	UnkOffMaybe      uint64 // 5FC000h
	UnkNumOfImgs     uint64 // C0000000h ? maybe just 0xC == 11 ?
	What             uint64 // C0035404h
	UnkSz2           uint64 // 5FC000h
	Something        uint64 // 26FC000h
	KernelDataOff    uint64 // 2D0C000h
	SomeSize2        uint64 // 334000h
	_                uint64 // padding ?
	AnotherSz        uint64 // 30000h ?
	_                uint64 // padding ?
	_                uint64 // padding ?
	YouAgain         uint64 // 30000h ?
	UnkSize4         uint64 // 74000h ?
	UnkSize5         uint64 // 40000h ?
	HelpMe           uint64 // C05FC000h ?
	UnkSize6         uint64 // 264000h ?
	Nooooooo         uint64 // 14000h ???
	SweetBaaaby      uint64 // C0670000h ??
	ImDead           uint64 // 70000h ??
	_                uint64 // padding ?
	Aaaagain         uint64 // 70000h ??
	UnkOffset6       uint64 // 2BC000h ???
	UnkOffset7       uint64 // 2D0C000h ???
	UnkOffset8       uint64 // 334000h ???
	Aaaaaaaaaagin    uint64 // 70000h ???
	_                uint64 // padding ?
	Aaaaaaaaaagin2   uint64 // 70000h ???
	UnkOffset9       uint64 // 2BC000h ???
	UnkOffset10      uint64 // 32C000h ???
	FooterOffset     uint64
	FooterSz         uint64
}

type Type4 struct {
	Unk0       uint32         // 1
	Unk1       uint32         // 0xc == 11
	_          uint64         // padding ?
	Unk2       uint64         // F000h
	_          [4]uint64      // padding ?
	Unk3       uint64         // C000h
	_          [2]uint64      // padding ?
	Unk4       uint64         // 3 ?
	_          uint64         // padding ?
	Unk5       uint64         // 16000h ?
	_          uint64         // padding ?
	_          uint64         // padding ?
	NumRanges  uint64         // 0xD == 12 ?
	UUID       types.UUID     // 636B62C3-4647-34F7-9089-A58256078A27
	_          uint64         // padding ?
	Unk7       uint64         // 14000h ?
	Unk7again  uint64         // 14000h ?
	Unk8       uint64         // 8000000h ?
	Unk9       uint64         // 1 ?
	_          uint64         // padding ?
	Unk10      uint64         // C000h ?
	Unk10again uint64         // C000h ?
	Unk11      uint64         // 8014000h ?
	Unk12      uint64         // 4 ?
	_          [3]uint64      // padding ?
	Unk13      uint64         // 8020000h ?
	Unk14      uint64         // 6 ?
	Unk15      uint64         // 8003E80h ?
	_          [36]uint64     // padding ?
	Unk17      uint64         // 0xa == 10 ?
	_          uint64         // padding ?
	Unk18      uint64         // 16000h ?
	Unk19      uint64         // 1582Ch ?
	_          uint64         // padding ?
	Unk20      uint64         // 0xa == 10 ?
	_          uint64         // padding ?
	Unk21      uint64         // F000h ?
	Ranges     [0xD]typ4Range // FIXME: this should be read AFTER the Type4 header is read
}

type typ4Range struct {
	Type   uint32
	Name   [4]byte
	Offset uint64
	Size   uint64
}

func (t4 typ4Range) String() string {
	slices.Reverse(t4.Name[:])
	if t4.Size == 0 {
		return fmt.Sprintf("typ=%d sz=%-10s off=0x%08x-0x%08x %s", t4.Type, fmt.Sprintf("%d", t4.Size), t4.Offset, t4.Offset+t4.Size, t4.Name)
	}
	return fmt.Sprintf("typ=%d sz=0x%08x off=0x%08x-0x%08x %s", t4.Type, t4.Size, t4.Offset, t4.Offset+t4.Size, t4.Name)
}

type Config struct {
	Unk1         int
	Unk2         int
	Assets       []Asset
	TOC          []TocEntry
	Compartments []Compartment
}

type Asset struct {
	Raw    asn1.RawContent
	Name   asn1.RawValue
	Type   int
	Offset int
	Size   int
}

func (h Asset) String() string {
	return fmt.Sprintf("%15s type=%d off=%#07x sz=%#x", h.Name.Bytes, h.Type, h.Offset, h.Size)
}

type TocEntry struct {
	Index int
	Entry asn1.RawValue `asn1:"optional"`
}

type TocEntryType struct {
	Name asn1.RawValue
	Type int
}

func (t TocEntry) GetEntry() *TocEntryType {
	if len(t.Entry.Bytes) > 0 {
		var typ TocEntryType
		if _, err := asn1.Unmarshal(t.Entry.Bytes, &typ); err == nil {
			return &typ
		}
	}
	return nil
}

func (t TocEntry) String() string {
	if entry := t.GetEntry(); entry != nil {
		return fmt.Sprintf("%3d) %15s type=%d", t.Index, entry.Name.Bytes, entry.Type)
	}
	return fmt.Sprintf("%3d) %s", t.Index, "nil")
}

type Compartment struct {
	Raw      asn1.RawContent
	AppUID   int
	Metadata []metadata
}

type metadata struct {
	Raw   asn1.RawContent
	Key   asn1.RawValue
	Value asn1.RawValue
}

type Endpoint struct {
	Type int
	Unk1 asn1.RawValue
	Unk2 asn1.RawValue
	Name asn1.RawValue
}

func (e Endpoint) String() string {
	return string(e.Name.Bytes)
}

func (md metadata) ParseValue() (any, error) {
	if bytes.HasPrefix(md.Key.Bytes, []byte("__COMPONENT")) {
		return string(md.Value.Bytes), nil
	}
	if bytes.HasPrefix(md.Key.Bytes, []byte("__ENDPOINT")) {
		var e Endpoint
		if _, err := asn1.Unmarshal(md.Value.Bytes, &e); err == nil {
			return e, nil
		} else {
			return nil, fmt.Errorf("failed to unmarshal bundle file info value: %v", err)
		}
	}
	if len(md.Value.Bytes) <= 8 {
		var num uint64
		for idx, b := range md.Value.Bytes {
			num |= uint64(b) << (8 * uint64(len(md.Value.Bytes)-1-idx))
		}
		return num, nil
	}
	return md.Value.Bytes, nil
}

func (md metadata) String() string {
	val, err := md.ParseValue()
	if err != nil {
		return fmt.Sprintf("[ERROR] failed to parse value: %v", err)
	}
	switch v := val.(type) {
	case string:
		return fmt.Sprintf("%s: %s", string(md.Key.Bytes), v)
	case Endpoint:
		return fmt.Sprintf("%s: %s", string(md.Key.Bytes), v)
	case uint64:
		if len(md.Value.Bytes) == 1 {
			return fmt.Sprintf("%s: %d", string(md.Key.Bytes), v)
		}
		return fmt.Sprintf("%s: %#x", string(md.Key.Bytes), v)
	default:
		return fmt.Sprintf("%s: %v", string(md.Key.Bytes), v)
	}
}

func (b *Bundle) ParseFiles() error {
	for _, bf := range b.Config.Compartments {
		var f File
		var sec Section
		var seg Segment
		entpoints := make(map[int]Endpoint, 0)
		for _, md := range bf.Metadata {
			val, err := md.ParseValue()
			if err != nil {
				return fmt.Errorf("failed to parse bundle file info value: %v", err)
			}
			if strings.EqualFold(string(md.Key.Bytes), "__COMPONENTNAME") {
				f.Name = val.(string)
			} else if strings.EqualFold(string(md.Key.Bytes), "__COMPONENTTYPE") {
				f.Type = val.(string)
			} else if _, secpart, ok := strings.Cut(string(md.Key.Bytes), "__MACHO__"); ok { // SECTION
				if name, _, ok := strings.Cut(secpart, "OFF"); ok {
					sec.Name = name
					sec.Offset = val.(uint64)
				}
				if name, _, ok := strings.Cut(secpart, "SZ"); ok {
					if sec.Name == "" {
						sec.Name = name
					}
					sec.Size = val.(uint64)
				}
				if sec.Name != "" && sec.Size != 0 {
					f.Sections = append(f.Sections, sec)
					sec = Section{}
				}
			} else if _, segpart, ok := strings.Cut(string(md.Key.Bytes), "__MACHO"); ok { // SEGMENT
				if name, _, ok := strings.Cut(segpart, "OFF"); ok {
					seg.Name = name
					seg.Offset = val.(uint64)
				}
				if name, _, ok := strings.Cut(segpart, "SZ"); ok {
					if seg.Name == "" {
						seg.Name = name
					}
					seg.Size = val.(uint64)
				}
				if seg.Name != "" && seg.Size != 0 {
					f.Segments = append(f.Segments, seg)
					seg = Segment{}
				}
			} else if _, idx, ok := strings.Cut(string(md.Key.Bytes), "__ENDPOINT__"); ok { // ENDPOINT
				if i, err := strconv.Atoi(idx); err == nil {
					entpoints[i] = val.(Endpoint)
				} else {
					return fmt.Errorf("failed to parse bundle file endpoint index: %v", err)
				}
			}
		}
		sort.Slice(f.Sections, func(i, j int) bool {
			return f.Sections[i].Offset < f.Sections[j].Offset
		})
		sort.Slice(f.Segments, func(i, j int) bool {
			return f.Segments[i].Offset < f.Segments[j].Offset
		})
		keys := make([]int, 0, len(entpoints))
		for k := range entpoints {
			keys = append(keys, k)
		}
		sort.Ints(keys)
		for _, k := range keys {
			f.Endpoints = append(f.Endpoints, entpoints[k])
		}
		b.Files = append(b.Files, f)
	}
	return nil
}

func Parse(in string) (*Bundle, error) {
	var bn Bundle

	f, err := os.Open(in)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer f.Close()

	if err := binary.Read(f, binary.LittleEndian, &bn.Header); err != nil {
		return nil, fmt.Errorf("failed to read bundle header: %v", err)
	}
	slices.Reverse(bn.Magic[:])

	if string(bn.Magic[:]) != Magic {
		return nil, fmt.Errorf("invalid magic: %s; expected 'BUND'", string(bn.Magic[:]))
	}

	switch bn.Type {
	case 3: // ExclaveCore
		var t3 Type3
		if err := binary.Read(f, binary.LittleEndian, &t3); err != nil {
			return nil, fmt.Errorf("failed to read bundle type 3: %v", err)
		}
		bn.TypeHeader = t3
		// parse footer/config
		if _, err := f.Seek(-int64(t3.FooterOffset), io.SeekEnd); err != nil {
			return nil, fmt.Errorf("failed to seek to bundle config data: %v", err)
		}

		fdata := make([]byte, t3.FooterSz)
		if _, err := f.Read(fdata); err != nil {
			return nil, fmt.Errorf("failed to read bundle data: %v", err)
		}

		if _, err = asn1.Unmarshal(fdata, &bn.Config); err != nil {
			return nil, fmt.Errorf("failed to ASN.1 parse bundle config: %v", err)
		}

		if err := bn.ParseFiles(); err != nil {
			return nil, fmt.Errorf("failed to parse bundle files: %v", err)
		}
	case 4: // AOP/DCP
		var t4 Type4
		if err := binary.Read(f, binary.LittleEndian, &t4); err != nil {
			return nil, fmt.Errorf("failed to read bundle type 4: %v", err)
		}
		bn.TypeHeader = t4
		// parse device tree/config
		dtreeRange := t4.Ranges[9]
		if _, err := f.Seek(int64(dtreeRange.Offset), io.SeekStart); err != nil {
			return nil, fmt.Errorf("failed to seek to bundle config data: %v", err)
		}
		dtdata := make([]byte, dtreeRange.Size)
		if _, err := f.Read(dtdata); err != nil {
			return nil, fmt.Errorf("failed to read bundle data: %v", err)
		}
		dt, err := devicetree.ParseData(bytes.NewReader(dtdata))
		if err != nil {
			return nil, fmt.Errorf("failed to parse device tree: %v", err)
		}
		slices.Reverse(dtreeRange.Name[:])
		log.WithField("name", string(dtreeRange.Name[:])).Debug("Device Tree")
		log.Debug(dt.String())
	default:
		return nil, fmt.Errorf("unknown bundle type: %d", bn.Type)
	}

	return &bn, nil
}
