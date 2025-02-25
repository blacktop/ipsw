package rcpi

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// credit: https://github.com/dhinakg/templates/blob/main/rcpi.tcl

type SectionType uint32

const (
	SectionTypeInfo SectionType = iota
	SectionTypeConfig
	SectionTypeDigest
	SectionTypeUnknown
	SectionTypeVerification
)

type Info struct {
	Version  [10]byte
	FileName [40]byte
}

type configFile struct {
	Unknown uint64
	Length  uint32
	Files   [][4]byte
}

type Config struct {
	Count uint32
	Files []configFile
}

type digestFile struct {
	Name   [4]byte
	Sha384 [48]byte
}

type Digest struct {
	Count   uint32
	Digests []digestFile
}

type unknownFileItem struct {
	Unknown uint32
	Type    [4]byte
}

type unknownFile struct {
	Unknown uint32
	Count   uint32
	Items   []unknownFileItem
}

type Unknown struct {
	Count    uint32
	Unknowns []unknownFile
}

type verificationFile struct {
	Name     [4]byte
	Verifier [4]byte
}

type Verification struct {
	Count         uint32
	Verifications []verificationFile
}

type Rcpi struct {
	Sections []any

	f *os.File
}

func Open(filename string) (*Rcpi, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	rcpi, err := Parse(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	rcpi.f = f
	return rcpi, nil
}

func (r *Rcpi) Close() error {
	return r.f.Close()
}

func Parse(r io.Reader) (*Rcpi, error) {
	var rcpi Rcpi
	var typ SectionType
	for {
		err := binary.Read(r, binary.LittleEndian, &typ)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		switch typ {
		case SectionTypeInfo:
			var info Info
			if err := binary.Read(r, binary.LittleEndian, &info); err != nil {
				return nil, err
			}
			rcpi.Sections = append(rcpi.Sections, info)
		case SectionTypeConfig:
			var config Config
			if err := binary.Read(r, binary.LittleEndian, &config.Count); err != nil {
				return nil, err
			}
			for range config.Count {
				var file configFile
				if err := binary.Read(r, binary.LittleEndian, &file.Unknown); err != nil {
					return nil, err
				}
				if err := binary.Read(r, binary.LittleEndian, &file.Length); err != nil {
					return nil, err
				}
				file.Files = make([][4]byte, file.Length/4)
				if err := binary.Read(r, binary.LittleEndian, &file.Files); err != nil {
					return nil, err
				}
				config.Files = append(config.Files, file)
			}
			rcpi.Sections = append(rcpi.Sections, config)
		case SectionTypeDigest:
			var digest Digest
			if err := binary.Read(r, binary.LittleEndian, &digest.Count); err != nil {
				return nil, err
			}
			for range digest.Count {
				var file digestFile
				if err := binary.Read(r, binary.LittleEndian, &file); err != nil {
					return nil, err
				}
				digest.Digests = append(digest.Digests, file)
			}
			rcpi.Sections = append(rcpi.Sections, digest)
		case SectionTypeUnknown:
			var unknown Unknown
			if err := binary.Read(r, binary.LittleEndian, &unknown.Count); err != nil {
				return nil, err
			}
			for range unknown.Count {
				var file unknownFile
				if err := binary.Read(r, binary.LittleEndian, &file.Unknown); err != nil {
					return nil, err
				}
				if err := binary.Read(r, binary.LittleEndian, &file.Count); err != nil {
					return nil, err
				}
				file.Items = make([]unknownFileItem, file.Count)
				if err := binary.Read(r, binary.LittleEndian, &file.Items); err != nil {
					return nil, err
				}
				unknown.Unknowns = append(unknown.Unknowns, file)
			}
			rcpi.Sections = append(rcpi.Sections, unknown)
		case SectionTypeVerification:
			var verification Verification
			if err := binary.Read(r, binary.LittleEndian, &verification.Count); err != nil {
				return nil, err
			}
			for range verification.Count {
				var file verificationFile
				if err := binary.Read(r, binary.LittleEndian, &file); err != nil {
					return nil, err
				}
				verification.Verifications = append(verification.Verifications, file)
			}
			rcpi.Sections = append(rcpi.Sections, verification)
		default:
			return nil, fmt.Errorf("unknown rcpi section type: %d", typ)
		}
	}
	return &rcpi, nil
}

func (r *Rcpi) String() string {
	var buf bytes.Buffer
	buf.WriteString("SECTIONS:\n")
	for _, section := range r.Sections {
		switch s := section.(type) {
		case Info:
			buf.WriteString("  Info\n")
			buf.WriteString(fmt.Sprintf("    Version: %s\n", string(s.Version[:])))
			buf.WriteString(fmt.Sprintf("    FileName: %s\n", string(s.FileName[:])))
		case Config:
			buf.WriteString("  Config\n")
			buf.WriteString(fmt.Sprintf("   Count: %d\n", s.Count))
			for _, file := range s.Files {
				buf.WriteString(fmt.Sprintf("    Unknown: %d\n", file.Unknown))
				for _, f := range file.Files {
					buf.WriteString(fmt.Sprintf("      - %s\n", string(f[:])))
				}
			}
		case Digest:
			buf.WriteString("  Digest\n")
			buf.WriteString(fmt.Sprintf("   Count: %d\n", s.Count))
			for _, file := range s.Digests {
				buf.WriteString(fmt.Sprintf("    - %s: %s\n", string(file.Name[:]), hex.EncodeToString(file.Sha384[:])))
			}
		case Unknown:
			buf.WriteString("  Unknown\n")
			buf.WriteString(fmt.Sprintf("   Count: %d\n", s.Count))
			for _, file := range s.Unknowns {
				buf.WriteString(fmt.Sprintf("    Unknown: %#x\n", file.Unknown))
				buf.WriteString(fmt.Sprintf("     Count: %d\n", file.Count))
				for _, item := range file.Items {
					buf.WriteString(fmt.Sprintf("      Unknown: %d\n", item.Unknown))
					buf.WriteString(fmt.Sprintf("      Type: %s\n", string(item.Type[:])))
				}
			}
		case Verification:
			buf.WriteString("  Verification\n")
			buf.WriteString(fmt.Sprintf("   Count: %d\n", s.Count))
			for _, file := range s.Verifications {
				buf.WriteString(fmt.Sprintf("    - %s (%s)\n", file.Name, file.Verifier))
			}
		}
	}
	return buf.String()
}
