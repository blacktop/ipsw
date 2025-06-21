// Package macho provides functionality for parsing Mach-O files.
package macho

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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
	All       bool
	Interface bool
	Deps      bool
	Demangle  bool
	Headers   bool

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
					quick.Highlight(os.Stdout, "/********\n* TYPES *\n********/\n\n", "swift", "terminal256", s.conf.Theme)
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
					quick.Highlight(os.Stdout, sout+"\n", "swift", "terminal256", s.conf.Theme)
					if i < (toc.Types-1) && (toc.Protocols > 0 || toc.ProtocolConformances > 0) { // skip last type if others follow
						quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "swift", "terminal256", s.conf.Theme)
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
					quick.Highlight(os.Stdout, "/************\n* PROTOCOLS *\n************/\n\n", "swift", "terminal256", s.conf.Theme)
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
					quick.Highlight(os.Stdout, sout+"\n", "swift", "terminal256", s.conf.Theme)
					if i < (toc.Protocols-1) && toc.ProtocolConformances > 0 { // skip last type if others follow
						quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "swift", "terminal256", s.conf.Theme)
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
					quick.Highlight(os.Stdout, "/************************\n* PROTOCOL CONFORMANCES *\n************************/\n\n", "swift", "terminal256", s.conf.Theme)
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
					quick.Highlight(os.Stdout, sout+"\n", "swift", "terminal256", s.conf.Theme)
					if i < (toc.ProtocolConformances - 1) { // skip last type if others follow
						quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "swift", "terminal256", s.conf.Theme)
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
					quick.Highlight(os.Stdout, "/*******************\n* ASSOCIATED TYPES *\n*******************/\n\n", "swift", "terminal256", s.conf.Theme)
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
					quick.Highlight(os.Stdout, sout+"\n", "swift", "terminal256", s.conf.Theme)
					quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "swift", "terminal256", s.conf.Theme)
				} else {
					fmt.Println(sout + "\n")
				}
			}
		} else if !errors.Is(err, macho.ErrSwiftSectionError) {
			log.Errorf("failed to parse swift associated types: %v", err)
		}
		if s.conf.All {
			fmt.Println("Swift (Other Sections)")
			fmt.Println("======================")
			fmt.Println()
			if entry, err := m.GetSwiftEntry(); err == nil {
				log.WithFields(log.Fields{
					"segment": "__TEXT",
					"section": "__swift5_entry",
				}).Info("Swift Entry")
				fmt.Println()
				fmt.Printf("%#x: entry\n\n", entry)
			} else if !errors.Is(err, macho.ErrSwiftSectionError) {
				log.Errorf("failed to parse swift entrypoint: %v", err)
			}
			if bins, err := m.GetSwiftBuiltinTypes(); err == nil {
				log.WithFields(log.Fields{
					"segment": "__TEXT",
					"section": "__swift5_builtin",
				}).Info("Swift Builtin Types")
				fmt.Println()
				for _, bin := range bins {
					if s.conf.Verbose {
						sout = bin.Verbose()
						if s.conf.Demangle {
							sout = swift.DemangleBlob(sout)
						}
					} else {
						sout = bin.String()
						if s.conf.Demangle {
							sout = swift.DemangleSimpleBlob(bin.String())
						}
					}
					if s.conf.Color {
						quick.Highlight(os.Stdout, sout+"\n", "swift", "terminal256", s.conf.Theme)
						quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "swift", "terminal256", s.conf.Theme)
					} else {
						fmt.Println(sout + "\n")
					}
				}
			} else if !errors.Is(err, macho.ErrSwiftSectionError) {
				log.Errorf("failed to parse swift built-in types: %v", err)
			}
			if metadatas, err := m.GetSwiftColocateMetadata(); err == nil {
				log.WithFields(log.Fields{
					"segment": "__TEXT",
					"section": "__textg_swiftm",
				}).Info("Swift Colocate Metadata")
				fmt.Println()
				for _, md := range metadatas {
					fmt.Println(md.Verbose())
				}
			} else if !errors.Is(err, macho.ErrSwiftSectionError) {
				log.Errorf("failed to parse swift colocate metadata: %v", err)
			}
			if mpenums, err := m.GetSwiftMultiPayloadEnums(); err == nil {
				log.WithFields(log.Fields{
					"segment": "__TEXT",
					"section": "__swift5_mpenum",
				}).Info("Swift MultiPayload Enums")
				fmt.Println()
				for _, mpenum := range mpenums {
					sout = mpenum.String()
					if s.conf.Demangle {
						sout = swift.DemangleSimpleBlob(mpenum.String())
					}
					if s.conf.Color {
						quick.Highlight(os.Stdout, sout+"\n", "swift", "terminal256", s.conf.Theme)
						quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "swift", "terminal256", s.conf.Theme)
					} else {
						fmt.Println(sout + "\n")
					}
				}
			} else if !errors.Is(err, macho.ErrSwiftSectionError) {
				log.Errorf("failed to parse swift multi-payload enums: %v", err)
			}
			if closures, err := m.GetSwiftClosures(); err == nil {
				log.WithFields(log.Fields{
					"segment": "__TEXT",
					"section": "__swift5_capture",
				}).Info("Swift Closures")
				fmt.Println()
				for _, closure := range closures {
					sout = closure.String()
					if s.conf.Demangle {
						sout = swift.DemangleSimpleBlob(closure.String())
					}
					if s.conf.Color {
						quick.Highlight(os.Stdout, sout+"\n", "swift", "terminal256", s.conf.Theme)
						quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "swift", "terminal256", s.conf.Theme)
					} else {
						fmt.Println(sout + "\n")
					}
				}
			} else if !errors.Is(err, macho.ErrSwiftSectionError) {
				log.Errorf("failed to parse swift closures: %v", err)
			}
			if rep, err := m.GetSwiftDynamicReplacementInfo(); err == nil {
				log.WithFields(log.Fields{
					"segment": "__TEXT",
					"section": "__swift5_replace",
				}).Info("Swift Dynamic Replacement Info")
				fmt.Println()
				if rep != nil {
					fmt.Println(rep)
				}
			} else if !errors.Is(err, macho.ErrSwiftSectionError) {
				log.Errorf("failed to parse swift dynamic replacement info: %v", err)
			}
			if rep, err := m.GetSwiftDynamicReplacementInfoForOpaqueTypes(); err == nil {
				log.WithFields(log.Fields{
					"segment": "__TEXT",
					"section": "__swift5_replac2",
				}).Info("Swift Dynamic Replacement Info For Opaque Types")
				fmt.Println()
				if rep != nil {
					fmt.Println(rep)
				}
			} else if !errors.Is(err, macho.ErrSwiftSectionError) {
				log.Errorf("failed to parse swift dynamic replacement info opaque types: %v", err)
			}
			if afuncs, err := m.GetSwiftAccessibleFunctions(); err == nil {
				log.WithFields(log.Fields{
					"segment": "__TEXT",
					"section": "__swift5_acfuncs",
				}).Info("Swift Accessible Functions")
				fmt.Println()
				for _, afunc := range afuncs {
					fmt.Println(afunc)
				}
			} else if !errors.Is(err, macho.ErrSwiftSectionError) {
				log.Errorf("failed to parse swift accessible functions: %v", err)
			}
		}
	}

	return nil
}

// Interface outputs Swift swift-dump interface from a MachO
func (s *Swift) Interface() error {
	if s.conf.Headers {
		return s.WriteHeaders()
	}

	// TODO: Implement single file interface generation
	return fmt.Errorf("single file interface generation not implemented yet")
}

func (s *Swift) WriteHeaders() error {
	writeSwiftHeaders := func(m *macho.File) error {
		var headers []string

		if !m.HasSwift() {
			return nil
		}

		if err := m.PreCache(); err != nil { // cache fields and types
			log.Errorf("failed to precache swift fields/types: %v", err)
		}

		var buildVersions []string
		if bvers := m.GetLoadsByName("LC_BUILD_VERSION"); len(bvers) > 0 {
			for _, bv := range bvers {
				buildVersions = append(buildVersions, bv.String())
			}
		}
		var sourceVersion string
		if svers := m.GetLoadsByName("LC_SOURCE_VERSION"); len(svers) > 0 {
			sourceVersion = svers[0].String()
		}

		/* generate Swift type headers */
		if types, err := m.GetSwiftTypes(); err == nil {
			for _, typ := range types {
				var sout string
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

				// Create a safe filename from the type name
				safeName := strings.ReplaceAll(typ.Name, ".", "_")
				safeName = strings.ReplaceAll(safeName, "<", "_")
				safeName = strings.ReplaceAll(safeName, ">", "_")
				safeName = strings.ReplaceAll(safeName, " ", "_")

				fname := filepath.Join(s.conf.Output, s.conf.Name, safeName+".swift")
				if err := writeSwiftHeader(&headerInfo{
					FileName:      fname,
					IpswVersion:   s.conf.IpswVersion,
					BuildVersions: buildVersions,
					SourceVersion: sourceVersion,
					Name:          safeName,
					Object:        sout,
				}); err != nil {
					return err
				}
				headers = append(headers, filepath.Base(fname))
			}
		} else if !errors.Is(err, macho.ErrSwiftSectionError) {
			log.Errorf("failed to parse swift types: %v", err)
		}

		/* generate Swift protocol headers */
		if protos, err := m.GetSwiftProtocols(); err == nil {
			for _, proto := range protos {
				var sout string
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

				// Create a safe filename from the protocol name
				safeName := strings.ReplaceAll(proto.Name, ".", "_")
				safeName = strings.ReplaceAll(safeName, "<", "_")
				safeName = strings.ReplaceAll(safeName, ">", "_")
				safeName = strings.ReplaceAll(safeName, " ", "_")

				fname := filepath.Join(s.conf.Output, s.conf.Name, safeName+"-Protocol.swift")
				if err := writeSwiftHeader(&headerInfo{
					FileName:      fname,
					IpswVersion:   s.conf.IpswVersion,
					BuildVersions: buildVersions,
					SourceVersion: sourceVersion,
					Name:          safeName + "_Protocol",
					Object:        sout,
				}); err != nil {
					return err
				}
				headers = append(headers, filepath.Base(fname))
			}
		} else if !errors.Is(err, macho.ErrSwiftSectionError) {
			log.Errorf("failed to parse swift protocols: %v", err)
		}

		/* generate Swift extension headers */
		if exts, err := m.GetSwiftProtocolConformances(); err == nil {
			for _, ext := range exts {
				var sout string
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

				// Create a safe filename from the extension info
				safeName := strings.ReplaceAll(ext.Protocol, ".", "_")
				safeName = strings.ReplaceAll(safeName, "<", "_")
				safeName = strings.ReplaceAll(safeName, ">", "_")
				safeName = strings.ReplaceAll(safeName, " ", "_")

				fname := filepath.Join(s.conf.Output, s.conf.Name, safeName+"-Extension.swift")
				if err := writeSwiftHeader(&headerInfo{
					FileName:      fname,
					IpswVersion:   s.conf.IpswVersion,
					BuildVersions: buildVersions,
					SourceVersion: sourceVersion,
					Name:          safeName + "_Extension",
					Object:        sout,
				}); err != nil {
					return err
				}
				headers = append(headers, filepath.Base(fname))
			}
		} else if !errors.Is(err, macho.ErrSwiftSectionError) {
			log.Errorf("failed to parse swift protocol conformances: %v", err)
		}

		/* generate Swift associated type headers */
		if asstyps, err := m.GetSwiftAssociatedTypes(); err == nil {
			for _, at := range asstyps {
				var sout string
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

				// Create a safe filename from the associated type info
				safeName := strings.ReplaceAll(at.ConformingTypeName, ".", "_")
				safeName = strings.ReplaceAll(safeName, "<", "_")
				safeName = strings.ReplaceAll(safeName, ">", "_")
				safeName = strings.ReplaceAll(safeName, " ", "_")

				fname := filepath.Join(s.conf.Output, s.conf.Name, safeName+"-AssociatedType.swift")
				if err := writeSwiftHeader(&headerInfo{
					FileName:      fname,
					IpswVersion:   s.conf.IpswVersion,
					BuildVersions: buildVersions,
					SourceVersion: sourceVersion,
					Name:          safeName + "_AssociatedType",
					Object:        sout,
				}); err != nil {
					return err
				}
				headers = append(headers, filepath.Base(fname))
			}
		} else if !errors.Is(err, macho.ErrSwiftSectionError) {
			log.Errorf("failed to parse swift associated types: %v", err)
		}

		/* generate umbrella header */
		if len(headers) > 0 {
			var umbrella string
			if slices.Contains(headers, s.conf.Name+".swift") {
				umbrella = s.conf.Name + "-Umbrella"
			} else {
				umbrella = s.conf.Name
			}

			for i, header := range headers {
				headers[i] = "import \"" + header + "\""
			}

			fname := filepath.Join(s.conf.Output, s.conf.Name, umbrella+".swift")
			if err := writeSwiftHeader(&headerInfo{
				FileName:      fname,
				IpswVersion:   s.conf.IpswVersion,
				BuildVersions: buildVersions,
				SourceVersion: sourceVersion,
				IsUmbrella:    true,
				Name:          strings.ReplaceAll(umbrella, "-", "_"),
				Object:        strings.Join(headers, "\n") + "\n",
			}); err != nil {
				return err
			}
		}

		return nil
	}

	if len(s.deps) > 0 {
		for _, m := range s.deps {
			if err := writeSwiftHeaders(m); err != nil {
				return err
			}
		}
	}

	return writeSwiftHeaders(s.file)
}

/* UTILS */

func writeSwiftHeader(hdr *headerInfo) error {
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

	if !hdr.IsUmbrella {
		out += "import Foundation\n\n"
	}

	out += fmt.Sprintf("%s\n", hdr.Object)

	if err := os.MkdirAll(filepath.Dir(hdr.FileName), 0o750); err != nil {
		return err
	}
	log.Infof("Creating %s", hdr.FileName)
	if err := os.WriteFile(hdr.FileName, []byte(out), 0644); err != nil {
		return fmt.Errorf("failed to write Swift header %s: %v", hdr.FileName, err)
	}

	return nil
}
