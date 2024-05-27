package bundle

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

const Magic = "DNUB"

type Bundle struct {
	bundleHdr
	Files  []File
	Config Config
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

func (f File) String() string {
	s := fmt.Sprintf("%s (%s)\n", f.Name, f.Type)
	for _, seg := range f.Segments {
		if seg.Size == 0 {
			continue
		}
		s += fmt.Sprintf("  sz=0x%08x off=0x%08x-0x%08x __%s\n", seg.Size, seg.Offset, seg.Offset+seg.Size, seg.Name)
		for _, sec := range f.Sections {
			if sec.Size == 0 {
				continue
			}
			if strings.HasPrefix(sec.Name, seg.Name) && !strings.EqualFold(sec.Name, seg.Name) {
				s += fmt.Sprintf("    sz=0x%08x off=0x%08x-0x%08x __%s\n", sec.Size, sec.Offset, sec.Offset+sec.Size, sec.Name)
			}
		}
	}
	if len(f.Endpoints) > 0 {
		s += "  Endpoints:\n"
		for i, ep := range f.Endpoints {
			s += fmt.Sprintf("    %3s) %s\n", fmt.Sprintf("%d", i+1), ep)
		}
	}
	return s
}

type bundleHdr struct {
	Unknown1 uint16
	Unknown2 uint16
	_        uint32  // padding ?
	Magic    [4]byte // "BUND"
}

type Config struct {
	Num1   int
	Num2   int
	Header []hdrPart
	TOC    []tocEntry
	Files  []Asn1File
}

type hdrPart struct {
	Raw    asn1.RawContent
	Name   asn1.RawValue
	Type   int
	Offset int
	Size   int
}

type tocEntry struct {
	Index int
	Entry asn1.RawValue `asn1:"optional"`
}

type Asn1File struct {
	Raw   asn1.RawContent
	Index int
	Info  []Info
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

type Info struct {
	Raw   asn1.RawContent
	Key   asn1.RawValue
	Value asn1.RawValue
}

func (i Info) ParseValue() (any, error) {
	if bytes.HasPrefix(i.Key.Bytes, []byte("__COMPONENT")) {
		return string(i.Value.Bytes), nil
	}
	if bytes.HasPrefix(i.Key.Bytes, []byte("__ENDPOINT")) {
		var e Endpoint
		if _, err := asn1.Unmarshal(i.Value.Bytes, &e); err == nil {
			return e, nil
		} else {
			return nil, fmt.Errorf("failed to unmarshal bundle file info value: %v", err)
		}
	}
	if len(i.Value.Bytes) <= 8 {
		var num uint64
		for idx, b := range i.Value.Bytes {
			num |= uint64(b) << (8 * uint64(len(i.Value.Bytes)-1-idx))
		}
		return num, nil
	}
	return i.Value.Bytes, nil
}

func (i Info) String() string {
	val, err := i.ParseValue()
	if err != nil {
		return fmt.Sprintf("[ERROR] failed to parse value: %v", err)
	}
	switch v := val.(type) {
	case string:
		return fmt.Sprintf("%s: %s", string(i.Key.Bytes), v)
	case Endpoint:
		return fmt.Sprintf("%s: %s", string(i.Key.Bytes), v)
	case uint64:
		if len(i.Value.Bytes) == 1 {
			return fmt.Sprintf("%s: %d", string(i.Key.Bytes), v)
		}
		return fmt.Sprintf("%s: %#x", string(i.Key.Bytes), v)
	default:
		return fmt.Sprintf("%s: %v", string(i.Key.Bytes), v)
	}
}

func (b *Bundle) ParseFiles() error {
	for _, bf := range b.Config.Files {
		var f File
		var sec Section
		var seg Segment
		entpoints := make(map[int]Endpoint, 0)
		for _, i := range bf.Info {
			val, err := i.ParseValue()
			if err != nil {
				return fmt.Errorf("failed to parse bundle file info value: %v", err)
			}
			if strings.EqualFold(string(i.Key.Bytes), "__COMPONENTNAME") {
				f.Name = val.(string)
			} else if strings.EqualFold(string(i.Key.Bytes), "__COMPONENTTYPE") {
				f.Type = val.(string)
			} else if _, secpart, ok := strings.Cut(string(i.Key.Bytes), "__MACHO__"); ok { // SECTION
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
			} else if _, segpart, ok := strings.Cut(string(i.Key.Bytes), "__MACHO"); ok { // SEGMENT
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
			} else if _, idx, ok := strings.Cut(string(i.Key.Bytes), "__ENDPOINT__"); ok { // ENDPOINT
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

	if err := binary.Read(f, binary.LittleEndian, &bn.bundleHdr); err != nil {
		return nil, fmt.Errorf("failed to read bundle header: %v", err)
	}

	if string(bn.Magic[:]) != Magic {
		return nil, fmt.Errorf("invalid magic: %s; expected 'DNUB'", string(bn.Magic[:]))
	}

	if _, err := f.Seek(-0x8000, io.SeekEnd); err != nil {
		return nil, fmt.Errorf("failed to seek to bundle config data: %v", err)
	}

	cdata := make([]byte, 0x8000)
	if _, err := f.Read(cdata); err != nil {
		return nil, fmt.Errorf("failed to read bundle data: %v", err)
	}

	if _, err = asn1.Unmarshal(cdata, &bn.Config); err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse bundle config: %v", err)
	}

	if err := bn.ParseFiles(); err != nil {
		return nil, fmt.Errorf("failed to parse bundle files: %v", err)
	}

	return &bn, nil
}
