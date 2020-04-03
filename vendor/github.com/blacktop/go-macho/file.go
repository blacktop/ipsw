package macho

// High level access to low level data structures.

import (
	"bytes"
	"compress/zlib"
	"debug/dwarf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"unsafe"

	"github.com/apex/log"
	"github.com/blacktop/go-macho/types"
)

const (
	pageAlign = 12 // 4096 = 1 << 12
)

type sections []*Section

// A File represents an open Mach-O file.
type File struct {
	FileTOC

	Symtab   *Symtab
	Dysymtab *Dysymtab

	closer io.Closer
}

type FileTOC struct {
	types.FileHeader
	ByteOrder binary.ByteOrder
	Loads     []Load
	Sections  sections
}

func (t *FileTOC) String() string {
	// note("Type = %s, Flags=0x%x", exem.Type, uint32(exem.Flags))
	// for i, l := range exem.Loads {
	// 	if s, ok := l.(*macho.Segment); ok {
	// 		fmt.Printf("Load %d is Segment %s, offset=0x%x, filesz=%d, addr=0x%x, memsz=%d, nsect=%d\n", i, s.Name,
	// 			s.Offset, s.Filesz, s.Addr, s.Memsz, s.Nsect)
	// 		for j := uint32(0); j < s.Nsect; j++ {
	// 			c := exem.Sections[j+s.Firstsect]
	// 			fmt.Printf("   Section %s, offset=0x%x, size=%d, addr=0x%x, flags=0x%x, nreloc=%d, res1=%d, res2=%d, res3=%d\n", c.Name, c.Offset, c.Size, c.Addr, c.Flags, c.Nreloc, c.Reserved1, c.Reserved2, c.Reserved3)
	// 		}
	// 	} else {
	// 		fmt.Printf("Load %d is %v\n", i, l)
	// 	}
	// }
	// if exem.SizeCommands != exem.LoadSize() {
	// 	fail("recorded command size %d does not equal computed command size %d", exem.SizeCommands, exem.LoadSize())
	// } else {
	// 	note("recorded command size %d, computed command size %d", exem.SizeCommands, exem.LoadSize())
	// }
	// note("File size is %d", exem.FileSize())
	return ""
}

func (t *FileTOC) AddLoad(l Load) {
	t.Loads = append(t.Loads, l)
	t.NCommands++
	t.SizeCommands += l.LoadSize(t)
}

// AddSegment adds segment s to the file table of contents,
// and also zeroes out the segment information with the expectation
// that this will be added next.
func (t *FileTOC) AddSegment(s *Segment) {
	t.AddLoad(s)
	s.Nsect = 0
	s.Firstsect = 0
}

// AddSection adds section to the most recently added Segment
func (t *FileTOC) AddSection(s *Section) {
	g := t.Loads[len(t.Loads)-1].(*Segment)
	if g.Nsect == 0 {
		g.Firstsect = uint32(len(t.Sections))
	}
	g.Nsect++
	t.Sections = append(t.Sections, s)
	sectionsize := uint32(unsafe.Sizeof(types.Section32{}))
	if g.Command() == types.LcSegment64 {
		sectionsize = uint32(unsafe.Sizeof(types.Section64{}))
	}
	t.SizeCommands += sectionsize
	g.Len += sectionsize
}

// DerivedCopy returns a modified copy of the TOC, with empty loads and sections,
// and with the specified header type and flags.
func (t *FileTOC) DerivedCopy(Type types.HeaderType, Flags types.HeaderFlag) *FileTOC {
	h := t.FileHeader
	h.NCommands, h.SizeCommands, h.Type, h.Flags = 0, 0, Type, Flags

	return &FileTOC{FileHeader: h, ByteOrder: t.ByteOrder}
}

// TOCSize returns the size in bytes of the object file representation
// of the header and Load Commands (including Segments and Sections, but
// not their contents) at the beginning of a Mach-O file.  This typically
// overlaps the text segment in the object file.
func (t *FileTOC) TOCSize() uint32 {
	return t.HdrSize() + t.LoadSize()
}

// LoadAlign returns the required alignment of Load commands in a binary.
// This is used to add padding for necessary alignment.
func (t *FileTOC) LoadAlign() uint64 {
	if t.Magic == types.Magic64 {
		return 8
	}
	return 4
}

// SymbolSize returns the size in bytes of a Symbol (Nlist32 or Nlist64)
func (t *FileTOC) SymbolSize() uint32 {
	if t.Magic == types.Magic64 {
		return uint32(unsafe.Sizeof(types.Nlist64{}))
	}
	return uint32(unsafe.Sizeof(types.Nlist32{}))
}

// HdrSize returns the size in bytes of the Macho header for a given
// magic number (where the magic number has been appropriately byte-swapped).
func (t *FileTOC) HdrSize() uint32 {
	switch t.Magic {
	case types.Magic32:
		return types.FileHeaderSize32
	case types.Magic64:
		return types.FileHeaderSize64
	case types.MagicFat:
		panic("MagicFat not handled yet")
	default:
		panic(fmt.Sprintf("Unexpected magic number 0x%x, expected Mach-O object file", t.Magic))
	}
}

// LoadSize returns the size of all the load commands in a file's table-of contents
// (but not their associated data, e.g., sections and symbol tables)
func (t *FileTOC) LoadSize() uint32 {
	cmdsz := uint32(0)
	for _, l := range t.Loads {
		s := l.LoadSize(t)
		cmdsz += s
	}
	return cmdsz
}

// FileSize returns the size in bytes of the header, load commands, and the
// in-file contents of all the segments and sections included in those
// load commands, accounting for their offsets within the file.
func (t *FileTOC) FileSize() uint64 {
	sz := uint64(t.LoadSize()) // ought to be contained in text segment, but just in case.
	for _, l := range t.Loads {
		if s, ok := l.(*Segment); ok {
			if m := s.Offset + s.Filesz; m > sz {
				sz = m
			}
		}
	}
	return sz
}

// Put writes the header and all load commands to buffer, using
// the byte ordering specified in FileTOC t.  For sections, this
// writes the headers that come in-line with the segment Load commands,
// but does not write the reference data for those sections.
func (t *FileTOC) Put(buffer []byte) int {
	next := t.FileHeader.Put(buffer, t.ByteOrder)
	for _, l := range t.Loads {
		if s, ok := l.(*Segment); ok {
			switch t.Magic {
			case types.Magic64:
				next += s.Put64(buffer[next:], t.ByteOrder)
				for i := uint32(0); i < s.Nsect; i++ {
					c := t.Sections[i+s.Firstsect]
					next += c.Put64(buffer[next:], t.ByteOrder)
				}
			case types.Magic32:
				next += s.Put32(buffer[next:], t.ByteOrder)
				for i := uint32(0); i < s.Nsect; i++ {
					c := t.Sections[i+s.Firstsect]
					next += c.Put32(buffer[next:], t.ByteOrder)
				}
			default:
				panic(fmt.Sprintf("Unexpected magic number 0x%x", t.Magic))
			}

		} else {
			next += l.Put(buffer[next:], t.ByteOrder)
		}
	}
	return next
}

/*
 * Mach-O reader
 */

// FormatError is returned by some operations if the data does
// not have the correct format for an object file.
type FormatError struct {
	off int64
	msg string
	val interface{}
}

func (e *FormatError) Error() string {
	msg := e.msg
	if e.val != nil {
		msg += fmt.Sprintf(" '%v'", e.val)
	}
	msg += fmt.Sprintf(" in record at byte %#x", e.off)
	return msg
}

func loadInSlice(c types.LoadCmd, list []types.LoadCmd) bool {
	for _, b := range list {
		if b == c {
			return true
		}
	}
	return false
}

// Open opens the named file using os.Open and prepares it for use as a Mach-O binary.
func Open(name string) (*File, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	ff, err := NewFile(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	ff.closer = f
	return ff, nil
}

// Close closes the File.
// If the File was created using NewFile directly instead of Open,
// Close has no effect.
func (f *File) Close() error {
	var err error
	if f.closer != nil {
		err = f.closer.Close()
		f.closer = nil
	}
	return err
}

// NewFile creates a new File for accessing a Mach-O binary in an underlying reader.
// The Mach-O binary is expected to start at position 0 in the ReaderAt.
func NewFile(r io.ReaderAt, loads ...types.LoadCmd) (*File, error) {
	f := new(File)
	sr := io.NewSectionReader(r, 0, 1<<63-1)

	// Read and decode Mach magic to determine byte order, size.
	// Magic32 and Magic64 differ only in the bottom bit.
	var ident [4]byte
	if _, err := r.ReadAt(ident[0:], 0); err != nil {
		return nil, err
	}
	be := binary.BigEndian.Uint32(ident[0:])
	le := binary.LittleEndian.Uint32(ident[0:])
	switch types.Magic32.Int() &^ 1 {
	case be &^ 1:
		f.ByteOrder = binary.BigEndian
		f.Magic = types.Magic(be)
	case le &^ 1:
		f.ByteOrder = binary.LittleEndian
		f.Magic = types.Magic(le)
	default:
		return nil, &FormatError{0, "invalid magic number", nil}
	}

	// Read entire file header.
	if err := binary.Read(sr, f.ByteOrder, &f.FileHeader); err != nil {
		return nil, err
	}

	// Then load commands.
	offset := int64(types.FileHeaderSize32)
	if f.Magic == types.Magic64 {
		offset = types.FileHeaderSize64
	}
	dat := make([]byte, f.SizeCommands)
	if _, err := r.ReadAt(dat, offset); err != nil {
		return nil, err
	}
	f.Loads = make([]Load, f.NCommands)
	bo := f.ByteOrder
	for i := range f.Loads {
		// Each load command begins with uint32 command and length.
		if len(dat) < 8 {
			return nil, &FormatError{offset, "command block too small", nil}
		}
		cmd, siz := types.LoadCmd(bo.Uint32(dat[0:4])), bo.Uint32(dat[4:8])
		if siz < 8 || siz > uint32(len(dat)) {
			return nil, &FormatError{offset, "invalid command block size", nil}
		}

		// skip unwanted load commands
		if len(loads) > 0 && !loadInSlice(cmd, loads) {
			continue
		}

		var cmddat []byte
		cmddat, dat = dat[0:siz], dat[siz:]
		offset += int64(siz)
		var s *Segment
		switch cmd {
		default:
			log.Warnf("found NEW load command: %s, please let the author know :)", cmd)
			f.Loads[i] = LoadCmdBytes{types.LoadCmd(cmd), LoadBytes(cmddat)}
		case types.LcSegment:
			var seg32 types.Segment32
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &seg32); err != nil {
				return nil, err
			}
			s = new(Segment)
			s.LoadBytes = cmddat
			s.LoadCmd = cmd
			s.Len = siz
			s.Name = cstring(seg32.Name[0:])
			s.Addr = uint64(seg32.Addr)
			s.Memsz = uint64(seg32.Memsz)
			s.Offset = uint64(seg32.Offset)
			s.Filesz = uint64(seg32.Filesz)
			s.Maxprot = seg32.Maxprot
			s.Prot = seg32.Prot
			s.Nsect = seg32.Nsect
			s.Flag = seg32.Flag
			f.Loads[i] = s
			for i := 0; i < int(s.Nsect); i++ {
				var sh32 types.Section32
				if err := binary.Read(b, bo, &sh32); err != nil {
					return nil, err
				}
				sh := new(Section)
				sh.Name = cstring(sh32.Name[0:])
				sh.Seg = cstring(sh32.Seg[0:])
				sh.Addr = uint64(sh32.Addr)
				sh.Size = uint64(sh32.Size)
				sh.Offset = sh32.Offset
				sh.Align = sh32.Align
				sh.Reloff = sh32.Reloff
				sh.Nreloc = sh32.Nreloc
				sh.Flags = sh32.Flags
				if err := f.pushSection(sh, r); err != nil {
					return nil, err
				}
			}
		case types.LcSegment64:
			var seg64 types.Segment64
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &seg64); err != nil {
				return nil, err
			}
			s = new(Segment)
			s.LoadBytes = cmddat
			s.LoadCmd = cmd
			s.Len = siz
			s.Name = cstring(seg64.Name[0:])
			s.Addr = seg64.Addr
			s.Memsz = seg64.Memsz
			s.Offset = seg64.Offset
			s.Filesz = seg64.Filesz
			s.Maxprot = seg64.Maxprot
			s.Prot = seg64.Prot
			s.Nsect = seg64.Nsect
			s.Flag = seg64.Flag
			f.Loads[i] = s
			for i := 0; i < int(s.Nsect); i++ {
				var sh64 types.Section64
				if err := binary.Read(b, bo, &sh64); err != nil {
					return nil, err
				}
				sh := new(Section)
				sh.Name = cstring(sh64.Name[0:])
				sh.Seg = cstring(sh64.Seg[0:])
				sh.Addr = sh64.Addr
				sh.Size = sh64.Size
				sh.Offset = sh64.Offset
				sh.Align = sh64.Align
				sh.Reloff = sh64.Reloff
				sh.Nreloc = sh64.Nreloc
				sh.Flags = sh64.Flags
				if err := f.pushSection(sh, r); err != nil {
					return nil, err
				}
			}
		case types.LcSymtab:
			var hdr types.SymtabCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, err
			}
			strtab := make([]byte, hdr.Strsize)
			if _, err := r.ReadAt(strtab, int64(hdr.Stroff)); err != nil {
				return f, nil
				// return nil, err
			}
			var symsz int
			if f.Magic == types.Magic64 {
				symsz = 16
			} else {
				symsz = 12
			}
			symdat := make([]byte, int(hdr.Nsyms)*symsz)
			if _, err := r.ReadAt(symdat, int64(hdr.Symoff)); err != nil {
				return nil, err
			}
			st, err := f.parseSymtab(symdat, strtab, cmddat, &hdr, offset)
			if err != nil {
				return nil, err
			}
			f.Loads[i] = st
			f.Symtab = st
		// TODO: case types.LcSymseg:
		// TODO: case types.LcThread:
		case types.LcUnixThread:
			var ut types.UnixThreadCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &ut); err != nil {
				return nil, err
			}
			l := new(UnixThread)
			l.LoadBytes = LoadBytes(cmddat)
			f.Loads[i] = l
		// TODO: case types.LcLoadfvmlib:
		// TODO: case types.LcIdfvmlib:
		// TODO: case types.LcIdent:
		// TODO: case types.LcFvmfile:
		// TODO: case types.LcPrepage:
		case types.LcDysymtab:
			var hdr types.DysymtabCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, err
			}
			dat := make([]byte, hdr.Nindirectsyms*4)
			if _, err := r.ReadAt(dat, int64(hdr.Indirectsymoff)); err != nil {
				return nil, err
			}
			x := make([]uint32, hdr.Nindirectsyms)
			if err := binary.Read(bytes.NewReader(dat), bo, x); err != nil {
				return nil, err
			}
			st := new(Dysymtab)
			st.LoadBytes = LoadBytes(cmddat)
			st.DysymtabCmd = hdr
			st.IndirectSyms = x
			f.Loads[i] = st
			f.Dysymtab = st
		case types.LcDylib:
			var hdr types.DylibCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, err
			}
			l := new(Dylib)
			if hdr.Name >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid name in dynamic library command", hdr.Name}
			}
			l.Name = cstring(cmddat[hdr.Name:])
			l.Time = hdr.Time
			l.CurrentVersion = hdr.CurrentVersion.String()
			l.CompatVersion = hdr.CompatVersion.String()
			l.LoadBytes = LoadBytes(cmddat)
			f.Loads[i] = l
		case types.LcDylibID:
			var hdr types.DylibCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, err
			}
			l := new(DylibID)
			if hdr.Name >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid name in dynamic library ident command", hdr.Name}
			}
			l.Name = cstring(cmddat[hdr.Name:])
			l.Time = hdr.Time
			l.CurrentVersion = hdr.CurrentVersion.String()
			l.CompatVersion = hdr.CompatVersion.String()
			l.LoadBytes = LoadBytes(cmddat)
			f.Loads[i] = l
		// TODO: case types.LcDylinker:
		// TODO: case types.LcDylinkerID:
		// TODO: case types.LcPreboundDylib:
		// TODO: case types.LcRoutines:
		case types.LcSubFramework:
			var sf types.SubFrameworkCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &sf); err != nil {
				return nil, err
			}
			l := new(SubFramework)
			if sf.Framework >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid framework in subframework command", sf.Framework}
			}
			l.Framework = cstring(cmddat[sf.Framework:])
			l.LoadBytes = LoadBytes(cmddat)
			f.Loads[i] = l
		// TODO: case types.LcSubUmbrella:
		case types.LcSubClient:
			var sc types.SubClientCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &sc); err != nil {
				return nil, err
			}
			l := new(SubClient)
			if sc.Client >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid path in sub client command", sc.Client}
			}
			l.Name = cstring(cmddat[sc.Client:])
			l.LoadBytes = LoadBytes(cmddat)
			f.Loads[i] = l
		// TODO: case types.LcSubLibrary:
		// TODO: case types.LcTwolevelHints:
		// TODO: case types.LcPrebindCksum:
		case types.LcLoadWeakDylib:
			var hdr types.DylibCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, err
			}
			l := new(WeakDylib)
			if hdr.Name >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid name in weak dynamic library command", hdr.Name}
			}
			l.Name = cstring(cmddat[hdr.Name:])
			l.Time = hdr.Time
			l.CurrentVersion = hdr.CurrentVersion.String()
			l.CompatVersion = hdr.CompatVersion.String()
			l.LoadBytes = LoadBytes(cmddat)
			f.Loads[i] = l
		case types.LcRoutines64:
			var r64 types.Routines64Cmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &r64); err != nil {
				return nil, err
			}
			l := new(Routines64)
			l.InitAddress = r64.InitAddress
			l.InitModule = r64.InitModule
			l.LoadBytes = LoadBytes(cmddat)
			f.Loads[i] = l
		case types.LcUUID:
			var u types.UUIDCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &u); err != nil {
				return nil, err
			}
			l := new(UUID)
			l.ID = u.UUID.String()
			l.LoadBytes = LoadBytes(cmddat)
			f.Loads[i] = l
		case types.LcRpath:
			var hdr types.RpathCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, err
			}
			l := new(Rpath)
			if hdr.Path >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid path in rpath command", hdr.Path}
			}
			l.Path = cstring(cmddat[hdr.Path:])
			l.LoadBytes = LoadBytes(cmddat)
			f.Loads[i] = l
		case types.LcCodeSignature:
			var hdr types.CodeSignatureCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, err
			}
			l := new(CodeSignature)
			l.Offset = hdr.Offset
			l.Size = hdr.Size
			l.LoadBytes = LoadBytes(cmddat)
			f.Loads[i] = l
		case types.LcSegmentSplitInfo:
			var hdr types.SegmentSplitInfoCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, err
			}
			l := new(SplitInfo)
			l.Offset = hdr.Offset
			l.Size = hdr.Size
			l.LoadBytes = LoadBytes(cmddat)
			f.Loads[i] = l
		case types.LcReexportDylib:
			var hdr types.ReExportDylibCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, err
			}
			l := new(ReExportDylib)
			if hdr.Name >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid name in dynamic library command", hdr.Name}
			}
			l.Name = cstring(cmddat[hdr.Name:])
			l.Time = hdr.Time
			l.CurrentVersion = hdr.CurrentVersion.String()
			l.CompatVersion = hdr.CompatVersion.String()
			l.LoadBytes = LoadBytes(cmddat)
			f.Loads[i] = l
		// TODO: case types.LcLazyLoadDylib:
		// TODO: case types.LcEncryptionInfo:
		case types.LcDyldInfo:
		case types.LcDyldInfoOnly:
			var info types.DyldInfoCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &info); err != nil {
				return nil, err
			}
			l := new(DyldInfo)
			l.RebaseOff = info.RebaseOff
			l.RebaseSize = info.RebaseSize
			l.BindOff = info.BindOff
			l.BindSize = info.BindSize
			l.WeakBindOff = info.WeakBindOff
			l.WeakBindSize = info.WeakBindSize
			l.LazyBindOff = info.LazyBindOff
			l.LazyBindSize = info.LazyBindSize
			l.ExportOff = info.ExportOff
			l.ExportSize = info.ExportSize
			f.Loads[i] = l
		case types.LcLoadUpwardDylib:
			var hdr types.UpwardDylibCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, err
			}
			l := new(UpwardDylib)
			if hdr.Name >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid name in load upwardl dylib command", hdr.Name}
			}
			l.Name = cstring(cmddat[hdr.Name:])
			l.Time = hdr.Time
			l.CurrentVersion = hdr.CurrentVersion.String()
			l.CompatVersion = hdr.CompatVersion.String()
			l.LoadBytes = LoadBytes(cmddat)
			f.Loads[i] = l
		case types.LcVersionMinMacosx:
			var verMin types.VersionMinMacOSCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &verMin); err != nil {
				return nil, err
			}
			l := new(VersionMinMacosx)
			l.Version = verMin.Version.String()
			l.Sdk = verMin.Sdk.String()
			l.LoadBytes = LoadBytes(cmddat)
			f.Loads[i] = l
		case types.LcVersionMinIphoneos:
			var verMin types.VersionMinIPhoneOSCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &verMin); err != nil {
				return nil, err
			}
			l := new(VersionMinIphoneos)
			l.Version = verMin.Version.String()
			l.Sdk = verMin.Sdk.String()
			l.LoadBytes = LoadBytes(cmddat)
			f.Loads[i] = l
		case types.LcFunctionStarts:
			var led types.LinkEditDataCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &led); err != nil {
				return nil, err
			}
			l := new(FunctionStarts)
			l.Offset = led.Offset
			l.Size = led.Size
			l.LoadBytes = LoadBytes(cmddat)
			f.Loads[i] = l
		// TODO: case types.LcDyldEnvironment:
		// TODO: case types.LcMain:
		case types.LcDataInCode:
			var led types.LinkEditDataCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &led); err != nil {
				return nil, err
			}
			l := new(DataInCode)
			// var e DataInCodeEntry

			l.LoadBytes = LoadBytes(cmddat)
			f.Loads[i] = l
		case types.LcSourceVersion:
			var sv types.SourceVersionCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &sv); err != nil {
				return nil, err
			}
			l := new(SourceVersion)
			l.Version = sv.Version.String()
			l.LoadBytes = LoadBytes(cmddat)
			f.Loads[i] = l
		// TODO: case types.LcDylibCodeSignDrs:
		// TODO: case types.LcEncryptionInfo64:
		// TODO: case types.LcLinkerOption:
		// TODO: case types.LcLinkerOptimizationHint:
		// TODO: case types.LcVersionMinTvos:
		// TODO: case types.LcVersionMinWatchos:
		// TODO: case types.LcNote:
		case types.LcBuildVersion:
			var build types.BuildVersionCmd
			var buildTool types.BuildToolVersion
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &build); err != nil {
				return nil, err
			}
			l := new(BuildVersion)
			l.Platform = build.Platform.String()
			l.Minos = build.Minos.String()
			l.Sdk = build.Sdk.String()
			l.NumTools = build.NumTools
			if build.NumTools > 0 {
				if err := binary.Read(b, bo, &buildTool); err != nil {
					return nil, err
				}
				l.Tool = buildTool.Tool.String()
				l.ToolVersion = buildTool.Version.String()
			}
			l.LoadBytes = LoadBytes(cmddat)
			f.Loads[i] = l
			// TODO: case types.LcDyldExportsTrie:
			// TODO: case types.LcDyldChainedFixups:
		}
		if s != nil {
			s.sr = io.NewSectionReader(r, int64(s.Offset), int64(s.Filesz))
			s.ReaderAt = s.sr
		}
	}
	return f, nil
}

func (f *File) parseSymtab(symdat, strtab, cmddat []byte, hdr *types.SymtabCmd, offset int64) (*Symtab, error) {
	bo := f.ByteOrder
	symtab := make([]Symbol, hdr.Nsyms)
	b := bytes.NewReader(symdat)
	for i := range symtab {
		var n types.Nlist64
		if f.Magic == types.Magic64 {
			if err := binary.Read(b, bo, &n); err != nil {
				return nil, err
			}
		} else {
			var n32 types.Nlist32
			if err := binary.Read(b, bo, &n32); err != nil {
				return nil, err
			}
			n.Name = n32.Name
			n.Type = n32.Type
			n.Sect = n32.Sect
			n.Desc = n32.Desc
			n.Value = uint64(n32.Value)
		}
		sym := &symtab[i]
		if n.Name >= uint32(len(strtab)) {
			return nil, &FormatError{offset, "invalid name in symbol table", n.Name}
		}
		// We add "_" to Go symbols. Strip it here. See issue 33808.
		name := cstring(strtab[n.Name:])
		if strings.Contains(name, ".") && name[0] == '_' {
			name = name[1:]
		}
		sym.Name = name
		sym.Type = n.Type
		sym.Sect = n.Sect
		sym.Desc = n.Desc
		sym.Value = n.Value
	}
	st := new(Symtab)
	st.LoadBytes = LoadBytes(cmddat)
	st.Syms = symtab
	return st, nil
}

type relocInfo struct {
	Addr   uint32
	Symnum uint32
}

func (f *File) pushSection(sh *Section, r io.ReaderAt) error {
	f.Sections = append(f.Sections, sh)
	sh.sr = io.NewSectionReader(r, int64(sh.Offset), int64(sh.Size))
	sh.ReaderAt = sh.sr

	if sh.Nreloc > 0 {
		reldat := make([]byte, int(sh.Nreloc)*8)
		if _, err := r.ReadAt(reldat, int64(sh.Reloff)); err != nil {
			return err
		}
		b := bytes.NewReader(reldat)

		bo := f.ByteOrder

		sh.Relocs = make([]Reloc, sh.Nreloc)
		for i := range sh.Relocs {
			rel := &sh.Relocs[i]

			var ri relocInfo
			if err := binary.Read(b, bo, &ri); err != nil {
				return err
			}

			if ri.Addr&(1<<31) != 0 { // scattered
				rel.Addr = ri.Addr & (1<<24 - 1)
				rel.Type = uint8((ri.Addr >> 24) & (1<<4 - 1))
				rel.Len = uint8((ri.Addr >> 28) & (1<<2 - 1))
				rel.Pcrel = ri.Addr&(1<<30) != 0
				rel.Value = ri.Symnum
				rel.Scattered = true
			} else {
				switch bo {
				case binary.LittleEndian:
					rel.Addr = ri.Addr
					rel.Value = ri.Symnum & (1<<24 - 1)
					rel.Pcrel = ri.Symnum&(1<<24) != 0
					rel.Len = uint8((ri.Symnum >> 25) & (1<<2 - 1))
					rel.Extern = ri.Symnum&(1<<27) != 0
					rel.Type = uint8((ri.Symnum >> 28) & (1<<4 - 1))
				case binary.BigEndian:
					rel.Addr = ri.Addr
					rel.Value = ri.Symnum >> 8
					rel.Pcrel = ri.Symnum&(1<<7) != 0
					rel.Len = uint8((ri.Symnum >> 5) & (1<<2 - 1))
					rel.Extern = ri.Symnum&(1<<4) != 0
					rel.Type = uint8(ri.Symnum & (1<<4 - 1))
				default:
					panic("unreachable")
				}
			}
		}
	}

	return nil
}

func cstring(b []byte) string {
	i := bytes.IndexByte(b, 0)
	if i == -1 {
		i = len(b)
	}
	return string(b[0:i])
}

// Segment returns the first Segment with the given name, or nil if no such segment exists.
func (f *File) Segment(name string) *Segment {
	for _, l := range f.Loads {
		if s, ok := l.(*Segment); ok && s.Name == name {
			return s
		}
	}
	return nil
}

// Segments returns all Segments.
func (f *File) Segments() []*Segment {
	var segs []*Segment
	for _, l := range f.Loads {
		if s, ok := l.(*Segment); ok {
			segs = append(segs, s)
		}
	}
	return segs
}

func (f *File) SegmentByName(segname string) *Segment {
	for _, seg := range f.Segments() {
		if seg.Name == segname {
			return seg
		}
	}

	return nil
}

// Section returns the first section with the given name, or nil if no such
// section exists.
func (f *File) Section(name string) *Section {
	for _, s := range f.Sections {
		if s.Name == name {
			return s
		}
	}
	return nil
}

func (f *File) SectionByName(seg, sect string) *Section {
	for _, sec := range f.Sections {
		if sec.Seg == seg && sec.Name == sect {
			return sec
		}
	}

	return nil
}

// UUID returns the UUID load command, or nil if no UUID exists.
func (f *File) UUID() *UUID {
	for _, l := range f.Loads {
		if u, ok := l.(*UUID); ok {
			return u
		}
	}
	return nil
}

// DylibID returns the dylib ID load command, or nil if no dylib ID exists.
func (f *File) DylibID() *DylibID {
	for _, l := range f.Loads {
		if s, ok := l.(*DylibID); ok {
			return s
		}
	}
	return nil
}

// DyldInfo returns the dyld info load command, or nil if no dyld info exists.
func (f *File) DyldInfo() *DyldInfo {
	for _, l := range f.Loads {
		if s, ok := l.(*DyldInfo); ok {
			return s
		}
	}
	return nil
}

// SourceVersion returns the source version load command, or nil if no source version exists.
func (f *File) SourceVersion() *SourceVersion {
	for _, l := range f.Loads {
		if s, ok := l.(*SourceVersion); ok {
			return s
		}
	}
	return nil
}

// BuildVersion returns the build version load command, or nil if no build version exists.
func (f *File) BuildVersion() *BuildVersion {
	for _, l := range f.Loads {
		if s, ok := l.(*BuildVersion); ok {
			return s
		}
	}
	return nil
}

// DWARF returns the DWARF debug information for the Mach-O file.
func (f *File) DWARF() (*dwarf.Data, error) {
	dwarfSuffix := func(s *Section) string {
		switch {
		case strings.HasPrefix(s.Name, "__debug_"):
			return s.Name[8:]
		case strings.HasPrefix(s.Name, "__zdebug_"):
			return s.Name[9:]
		default:
			return ""
		}

	}
	sectionData := func(s *Section) ([]byte, error) {
		b, err := s.Data()
		if err != nil && uint64(len(b)) < s.Size {
			return nil, err
		}

		if len(b) >= 12 && string(b[:4]) == "ZLIB" {
			dlen := binary.BigEndian.Uint64(b[4:12])
			dbuf := make([]byte, dlen)
			r, err := zlib.NewReader(bytes.NewBuffer(b[12:]))
			if err != nil {
				return nil, err
			}
			if _, err := io.ReadFull(r, dbuf); err != nil {
				return nil, err
			}
			if err := r.Close(); err != nil {
				return nil, err
			}
			b = dbuf
		}
		return b, nil
	}

	// There are many other DWARF sections, but these
	// are the ones the debug/dwarf package uses.
	// Don't bother loading others.
	var dat = map[string][]byte{"abbrev": nil, "info": nil, "str": nil, "line": nil, "ranges": nil}
	for _, s := range f.Sections {
		suffix := dwarfSuffix(s)
		if suffix == "" {
			continue
		}
		if _, ok := dat[suffix]; !ok {
			continue
		}
		b, err := sectionData(s)
		if err != nil {
			return nil, err
		}
		dat[suffix] = b
	}

	d, err := dwarf.New(dat["abbrev"], nil, nil, dat["info"], dat["line"], nil, dat["ranges"], dat["str"])
	if err != nil {
		return nil, err
	}

	// Look for DWARF4 .debug_types sections.
	for i, s := range f.Sections {
		suffix := dwarfSuffix(s)
		if suffix != "types" {
			continue
		}

		b, err := sectionData(s)
		if err != nil {
			return nil, err
		}

		err = d.AddTypes(fmt.Sprintf("types-%d", i), b)
		if err != nil {
			return nil, err
		}
	}

	return d, nil
}

// ImportedSymbols returns the names of all symbols
// referred to by the binary f that are expected to be
// satisfied by other libraries at dynamic load time.
func (f *File) ImportedSymbols() ([]string, error) {
	if f.Dysymtab == nil || f.Symtab == nil {
		return nil, &FormatError{0, "missing symbol table", nil}
	}

	st := f.Symtab
	dt := f.Dysymtab
	var all []string
	for _, s := range st.Syms[dt.Iundefsym : dt.Iundefsym+dt.Nundefsym] {
		all = append(all, s.Name)
	}
	return all, nil
}

// ImportedLibraries returns the paths of all libraries
// referred to by the binary f that are expected to be
// linked with the binary at dynamic link time.
func (f *File) ImportedLibraries() ([]string, error) {
	var all []string
	for _, l := range f.Loads {
		if lib, ok := l.(*Dylib); ok {
			all = append(all, lib.Name)
		}
	}
	return all, nil
}

func (f *File) FindSymbolAddress(symbol string) (uint64, error) {
	for _, sym := range f.Symtab.Syms {
		if strings.EqualFold(sym.Name, symbol) {
			return sym.Value, nil
		}
	}
	return 0, fmt.Errorf("symbol not found in macho symtab")
}

func (f *File) FindAddressSymbol(addr uint64) (string, error) {
	for _, sym := range f.Symtab.Syms {
		if sym.Value == addr {
			return sym.Name, nil
		}
	}
	return "", fmt.Errorf("symbol not found in macho symtab")
}
