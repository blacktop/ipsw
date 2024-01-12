// Package macho provides functionality for parsing Mach-O files.
package macho

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/alecthomas/chroma/v2/quick"
	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/swift"
	"github.com/blacktop/ipsw/pkg/dyld"
)

// ErrNoSwift is returned when a MachO does not contain swift info
var ErrNoSwift = errors.New("macho does not contain swift info")

// SwiftConfig for MachO Swift parser
type SwiftConfig struct {
	Name      string
	Verbose   bool
	Addrs     bool // TODO: implement in swift string formatters
	Interface bool
	Deps      bool
	Demangle  bool

	IpswVersion string

	Color  bool
	Theme  string
	Output string
}

// Swift represents a MachO Swift parser
type Swift struct {
	conf  *SwiftConfig
	file  *macho.File
	cache *dyld.File
	deps  []*macho.File
}

// NewSwift returns a new MachO Swift parser instance
func NewSwift(file *macho.File, dsc *dyld.File, conf *SwiftConfig) (*Swift, error) {
	if !file.HasObjC() {
		return nil, ErrNoObjc
	}

	s := &Swift{
		conf:  conf,
		file:  file,
		cache: dsc,
	}

	if s.conf.Deps {
		if dsc == nil {
			return nil, fmt.Errorf("dyld shared cache is required to dump imported private frameworks")
		}
		var deps []string
		for _, imp := range file.ImportedLibraries() {
			if s.conf.Interface {
				// only dump private frameworks when generating headers
				if strings.Contains(imp, "PrivateFrameworks") {
					deps = append(deps, imp)
				}
			} else {
				deps = append(deps, imp)
			}
		}
		for _, imageName := range deps {
			img, err := s.cache.Image(imageName)
			if err != nil {
				return nil, err
			}
			m, err := img.GetMacho()
			if err != nil {
				return nil, err
			}
			s.deps = append(s.deps, m)
		}
	}

	return s, nil
}

// DumpType returns Swift types matching a given pattern from a MachO
func (s *Swift) DumpType(pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("failed to compile regex: %v", err)
	}
	ms := []*macho.File{s.file}
	if s.conf.Deps {
		ms = append(ms, s.deps...)
	}
	for _, m := range ms {
		if !m.HasSwift() {
			return ErrNoSwift
		}

		toc := m.GetSwiftTOC()
		if err := m.PreCache(); err != nil { // cache fields and types
			log.Errorf("failed to precache swift fields/types: %v", err)
		}

		typs, err := m.GetSwiftTypes()
		if err != nil {
			if errors.Is(err, macho.ErrSwiftSectionError) {
				continue // skip to next MachO
			}
			return err
		}

		var sout string
		for i, typ := range typs {
			if re.MatchString(typ.Name) {
				if s.conf.Verbose {
					sout = typ.Verbose()
					if s.conf.Demangle {
						sout = swift.DemangleBlob(sout)
					}
				} else {
					sout = typ.String()
					if s.conf.Demangle {
						sout = swift.DemangleSimpleBlob(typ.String())
					}
				}
				if s.conf.Color {
					quick.Highlight(os.Stdout, sout+"\n", "swift", "terminal256", s.conf.Theme)
					if i < (toc.Types - 1) { // skip last
						quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "swift", "terminal256", s.conf.Theme)
					} else {
						fmt.Println()
					}
				} else {
					fmt.Println(sout + "\n")
				}
			}
		}
	}

	return nil
}

// DumpProtocol returns Swift protocols matching a given pattern from a MachO
func (s *Swift) DumpProtocol(pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("failed to compile regex: %v", err)
	}
	ms := []*macho.File{s.file}
	if s.conf.Deps {
		ms = append(ms, s.deps...)
	}
	for _, m := range ms {
		if !m.HasSwift() {
			return ErrNoSwift
		}

		toc := m.GetSwiftTOC()
		if err := m.PreCache(); err != nil { // cache fields and types
			log.Errorf("failed to precache swift fields/types: %v", err)
		}

		protos, err := m.GetSwiftProtocols()
		if err != nil {
			if errors.Is(err, macho.ErrSwiftSectionError) {
				continue // skip to next MachO
			}
			return err
		}

		var sout string
		for i, proto := range protos {
			if re.MatchString(proto.Name) {
				if s.conf.Verbose {
					sout = proto.Verbose()
					if s.conf.Demangle {
						sout = swift.DemangleBlob(sout)
					}
				} else {
					sout = proto.String()
					if s.conf.Demangle {
						sout = swift.DemangleSimpleBlob(proto.String())
					}
				}
				if s.conf.Color {
					quick.Highlight(os.Stdout, sout+"\n", "swift", "terminal256", s.conf.Theme)
					if i < (toc.Protocols - 1) { // skip last
						quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "swift", "terminal256", s.conf.Theme)
					} else {
						fmt.Println()
					}
				} else {
					fmt.Println(sout + "\n")
				}
			}
		}
	}

	return nil
}

// DumpExtension returns Swift extensions matching a given pattern from a MachO
func (s *Swift) DumpExtension(pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("failed to compile regex: %v", err)
	}
	ms := []*macho.File{s.file}
	if s.conf.Deps {
		ms = append(ms, s.deps...)
	}
	for _, m := range ms {
		if !m.HasSwift() {
			return ErrNoSwift
		}

		toc := m.GetSwiftTOC()
		if err := m.PreCache(); err != nil { // cache fields and types
			log.Errorf("failed to precache swift fields/types: %v", err)
		}

		exts, err := m.GetSwiftProtocolConformances()
		if err != nil {
			if errors.Is(err, macho.ErrSwiftSectionError) {
				continue // skip to next MachO
			}
			return err
		}

		var sout string
		for i, ext := range exts {
			if re.MatchString(ext.Protocol) {
				if s.conf.Verbose {
					sout = ext.Verbose()
					if s.conf.Demangle {
						sout = swift.DemangleBlob(sout)
					}
				} else {
					sout = ext.String()
					if s.conf.Demangle {
						sout = swift.DemangleSimpleBlob(ext.String())
					}
				}
				if s.conf.Color {
					quick.Highlight(os.Stdout, sout+"\n", "swift", "terminal256", s.conf.Theme)
					if i < (toc.ProtocolConformances - 1) { // skip last
						quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "swift", "terminal256", s.conf.Theme)
					} else {
						fmt.Println()
					}
				} else {
					fmt.Println(sout + "\n")
				}
			}
		}
	}

	return nil
}

// DumpAssociatedType returns Swift associated types matching a given pattern from a MachO
func (s *Swift) DumpAssociatedType(pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("failed to compile regex: %v", err)
	}
	ms := []*macho.File{s.file}
	if s.conf.Deps {
		ms = append(ms, s.deps...)
	}
	for _, m := range ms {
		if !m.HasSwift() {
			return ErrNoSwift
		}

		toc := m.GetSwiftTOC()
		if err := m.PreCache(); err != nil { // cache fields and types
			log.Errorf("failed to precache swift fields/types: %v", err)
		}

		asstyps, err := m.GetSwiftAssociatedTypes()
		if err != nil {
			if errors.Is(err, macho.ErrSwiftSectionError) {
				continue // skip to next MachO
			}
			return err
		}

		var sout string
		for i, typ := range asstyps {
			if re.MatchString(typ.ConformingTypeName) { // FIXME: is this the right field to match on?
				if s.conf.Verbose {
					sout = typ.Verbose()
					if s.conf.Demangle {
						sout = swift.DemangleBlob(sout)
					}
				} else {
					sout = typ.String()
					if s.conf.Demangle {
						sout = swift.DemangleSimpleBlob(typ.String())
					}
				}
				if s.conf.Color {
					quick.Highlight(os.Stdout, sout+"\n", "swift", "terminal256", s.conf.Theme)
					if i < (toc.AssociatedTypes - 1) { // skip last
						quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "swift", "terminal256", s.conf.Theme)
					} else {
						fmt.Println()
					}
				} else {
					fmt.Println(sout + "\n")
				}
			}
		}
	}

	return nil
}

// Dump outputs Swift info from a MachO
func (s *Swift) Dump() error {
	ms := []*macho.File{s.file}
	if s.conf.Deps {
		ms = append(ms, s.deps...)
	}
	for _, m := range ms {
		if !m.HasSwift() {
			return ErrNoSwift
		}
		toc := m.GetSwiftTOC()
		if s.conf.Verbose {
			fmt.Println(toc)
		}

		if err := m.PreCache(); err != nil { // cache fields and types
			log.Errorf("failed to precache swift fields/types: %v", err)
		}

		var sout string

		/* Swift Types */
		if typs, err := m.GetSwiftTypes(); err == nil {
			if s.conf.Verbose {
				if s.conf.Color {
					quick.Highlight(os.Stdout, "/********\n* TYPES *\n********/\n\n", "swift", "terminal256", "nord")
				} else {
					fmt.Println("TYPES")
					fmt.Print("-----\n\n")
				}
			}
			for i, typ := range typs {
				if s.conf.Verbose {
					sout = typ.Verbose()
					if s.conf.Demangle {
						sout = swift.DemangleBlob(sout)
					}
				} else {
					sout = typ.String()
					if s.conf.Demangle {
						sout = swift.DemangleSimpleBlob(typ.String())
					}
				}
				if s.conf.Color {
					quick.Highlight(os.Stdout, sout+"\n", "swift", "terminal256", "nord")
					if i < (toc.Types-1) && (toc.Protocols > 0 || toc.ProtocolConformances > 0) { // skip last type if others follow
						quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "swift", "terminal256", "nord")
					} else {
						fmt.Println()
					}
				} else {
					fmt.Println(sout + "\n")
				}
			}
		} else if !errors.Is(err, macho.ErrSwiftSectionError) {
			log.Errorf("failed to parse swift types: %v", err)
		}
		/* Swift Protocols */
		if protos, err := m.GetSwiftProtocols(); err == nil {
			if s.conf.Verbose {
				if s.conf.Color {
					quick.Highlight(os.Stdout, "/************\n* PROTOCOLS *\n************/\n\n", "swift", "terminal256", "nord")
				} else {
					fmt.Println("PROTOCOLS")
					fmt.Print("---------\n\n")
				}
			}
			for i, proto := range protos {
				if s.conf.Verbose {
					sout = proto.Verbose()
					if s.conf.Demangle {
						sout = swift.DemangleBlob(sout)
					}
				} else {
					sout = proto.String()
					if s.conf.Demangle {
						sout = swift.DemangleSimpleBlob(proto.String())
					}
				}
				if s.conf.Color {
					quick.Highlight(os.Stdout, sout+"\n", "swift", "terminal256", "nord")
					if i < (toc.Protocols-1) && toc.ProtocolConformances > 0 { // skip last type if others follow
						quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "swift", "terminal256", "nord")
					} else {
						fmt.Println()
					}
				} else {
					fmt.Println(sout + "\n")
				}
			}
		} else if !errors.Is(err, macho.ErrSwiftSectionError) {
			log.Errorf("failed to parse swift protocols: %v", err)
		}
		/* Swift Extensions */
		if protos, err := m.GetSwiftProtocolConformances(); err == nil {
			if s.conf.Verbose {
				if s.conf.Color {
					quick.Highlight(os.Stdout, "/************************\n* PROTOCOL CONFORMANCES *\n************************/\n\n", "swift", "terminal256", "nord")
				} else {
					fmt.Println("PROTOCOL CONFORMANCES")
					fmt.Print("---------------------\n\n")
				}
			}
			for i, proto := range protos {
				if s.conf.Verbose {
					sout = proto.Verbose()
					if s.conf.Demangle {
						sout = swift.DemangleBlob(sout)
					}
				} else {
					sout = proto.String()
					if s.conf.Demangle {
						sout = swift.DemangleSimpleBlob(proto.String())
					}
				}
				if s.conf.Color {
					quick.Highlight(os.Stdout, sout+"\n", "swift", "terminal256", "nord")
					if i < (toc.ProtocolConformances - 1) { // skip last type if others follow
						quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "swift", "terminal256", "nord")
					} else {
						fmt.Println()
					}
				} else {
					fmt.Println(sout + "\n")
				}
			}
		} else if !errors.Is(err, macho.ErrSwiftSectionError) {
			log.Errorf("failed to parse swift protocol conformances: %v", err)
		}
		/* Swift Associated Types */
		if asstyps, err := m.GetSwiftAssociatedTypes(); err == nil {
			if s.conf.Verbose {
				if s.conf.Color {
					quick.Highlight(os.Stdout, "/*******************\n* ASSOCIATED TYPES *\n*******************/\n\n", "swift", "terminal256", "nord")
				} else {
					fmt.Println("ASSOCIATED TYPES")
					fmt.Print("---------------------\n\n")
				}
			}
			for _, at := range asstyps {
				if s.conf.Verbose {
					sout = at.Verbose()
					if s.conf.Demangle {
						sout = swift.DemangleBlob(sout)
					}
				} else {
					sout = at.String()
					if s.conf.Demangle {
						sout = swift.DemangleSimpleBlob(at.String())
					}
				}
				if s.conf.Color {
					quick.Highlight(os.Stdout, sout+"\n", "swift", "terminal256", "nord")
					quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "swift", "terminal256", "nord")
				} else {
					fmt.Println(sout + "\n")
				}
			}
		} else if !errors.Is(err, macho.ErrSwiftSectionError) {
			log.Errorf("failed to parse swift associated types: %v", err)
		}
	}

	return nil
}

// Interface outputs Swift swift-dump interface from a MachO
func (s *Swift) Interface() error {
	panic("not implemented")
}

/* UTILS */

func writeInterface(hdr *headerInfo) error {
	out := fmt.Sprintf(
		"//\n"+
			"//   Generated by https://github.com/blacktop/ipsw (%s)\n"+
			"//\n"+
			"//    - LC_BUILD_VERSION:  %s\n"+
			"//    - LC_SOURCE_VERSION: %s\n"+
			"//\n",
		hdr.IpswVersion,
		strings.Join(hdr.BuildVersions, "\n//    - LC_BUILD_VERSION:  "),
		hdr.SourceVersion)

	if err := os.MkdirAll(filepath.Dir(hdr.FileName), 0o750); err != nil {
		return err
	}
	log.Infof("Creating %s", hdr.FileName)
	if err := os.WriteFile(hdr.FileName, []byte(out), 0644); err != nil {
		return fmt.Errorf("failed to write header %s: %v", hdr.FileName, err)
	}

	return nil
}
