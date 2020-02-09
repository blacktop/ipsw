package macho

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/macho/commands"
	"github.com/blacktop/ipsw/pkg/macho/header"
	"github.com/blacktop/ipsw/pkg/macho/types"
)

func loadInSlice(c commands.LoadCmd, list []commands.LoadCmd) bool {
	for _, b := range list {
		if b == c {
			return true
		}
	}
	return false
}

// NewFileFromDyld creates a new File for accessing an in-cache Dylib data in an underlying reader.
// The Dylib data buffer is expected to start at position 0 in the ReaderAt.
func NewFileFromDyld(r io.ReaderAt, loads ...commands.LoadCmd) (*File, error) {
	// func NewFileFromDyld(r io.ReaderAt, vmaToOffsetMap map[uint64]uint64) (*File, error) {
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
	switch header.Magic32.Int() &^ 1 {
	case be &^ 1:
		f.ByteOrder = binary.BigEndian
		f.Magic = header.Magic(be)
	case le &^ 1:
		f.ByteOrder = binary.LittleEndian
		f.Magic = header.Magic(le)
	default:
		return nil, &FormatError{0, "invalid magic number", nil}
	}

	// Read entire file header.
	if err := binary.Read(sr, f.ByteOrder, &f.FileHeader); err != nil {
		return nil, err
	}
	// Then load commands.
	offset := int64(header.FileHeaderSize32)
	if f.Magic == header.Magic64 {
		offset = header.FileHeaderSize64
	}
	dat := make([]byte, f.Cmdsz)
	if _, err := r.ReadAt(dat, offset); err != nil {
		return nil, err
	}
	f.Loads = make([]Load, f.Ncmd)
	bo := f.ByteOrder
	for i := range f.Loads {
		// Each load command begins with uint32 command and length.
		if len(dat) < 8 {
			return nil, &FormatError{offset, "command block too small", nil}
		}
		cmd, siz := commands.LoadCmd(bo.Uint32(dat[0:4])), bo.Uint32(dat[4:8])
		if siz < 8 || siz > uint32(len(dat)) {
			return nil, &FormatError{offset, "invalid command block size", nil}
		}
		// skip unwanted load commands
		if !loadInSlice(cmd, loads) {
			continue
		}

		var cmddat []byte
		cmddat, dat = dat[0:siz], dat[siz:]
		offset += int64(siz)
		var s *Segment
		switch cmd {
		default:
			log.Warnf("found NEW load command: %s", cmd)
			f.Loads[i] = LoadBytes(cmddat)
		case commands.LoadCmdSegment:
			var seg32 commands.Segment32
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &seg32); err != nil {
				return nil, err
			}
			s = new(Segment)
			s.LoadBytes = cmddat
			s.Cmd = cmd
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
				var sh32 commands.Section32
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
		case commands.LoadCmdSegment64:
			var seg64 commands.Segment64
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &seg64); err != nil {
				return nil, err
			}
			s = new(Segment)
			s.LoadBytes = cmddat
			s.Cmd = cmd
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
				var sh64 commands.Section64
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
		case commands.LoadCmdSymtab:
			var hdr commands.SymtabCmd
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
			if f.Magic == header.Magic64 {
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
		// case commands.LoadCmdSymseg:
		// case commands.LoadCmdThread:
		case commands.LoadCmdUnixThread:
			var ut commands.UnixThreadCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &ut); err != nil {
				return nil, err
			}
			l := new(UnixThread)
			l.LoadBytes = LoadBytes(cmddat)
			f.Loads[i] = l
		// case commands.LoadCmdLoadfvmlib:
		// case commands.LoadCmdIdfvmlib:
		// case commands.LoadCmdIdent:
		// case commands.LoadCmdFvmfile:
		// case commands.LoadCmdPrepage:
		case commands.LoadCmdDysymtab:
			var hdr commands.DysymtabCmd
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
		case commands.LoadCmdDylib:
			var hdr commands.DylibCmd
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
		case commands.LoadCmdDylibID:
			var hdr commands.DylibCmd
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
		// case commands.LoadCmdDylinker:
		// case commands.LoadCmdDylinkerID:
		// case commands.LoadCmdPreboundDylib:
		// case commands.LoadCmdRoutines:
		case commands.LoadCmdSubFramework:
			var sf commands.SubFrameworkCmd
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
		// case commands.LoadCmdSubUmbrella:
		case commands.LoadCmdSubClient:
			var sc commands.SubClientCmd
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
		// case commands.LoadCmdSubLibrary:
		// case commands.LoadCmdTwolevelHints:
		// case commands.LoadCmdPrebindCksum:
		case commands.LoadCmdLoadWeakDylib:
			var hdr commands.DylibCmd
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
		case commands.LoadCmdRoutines64:
			var r64 commands.Routines64Cmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &r64); err != nil {
				return nil, err
			}
			l := new(Routines64)
			l.InitAddress = r64.InitAddress
			l.InitModule = r64.InitModule
			l.LoadBytes = LoadBytes(cmddat)
			f.Loads[i] = l
		case commands.LoadCmdUUID:
			var u commands.UUIDCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &u); err != nil {
				return nil, err
			}
			l := new(UUID)
			l.ID = u.UUID.String()
			l.LoadBytes = LoadBytes(cmddat)
			f.Loads[i] = l
		case commands.LoadCmdRpath:
			var hdr commands.RpathCmd
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
		// case commands.LoadCmdCodeSignature:
		// case commands.LoadCmdSegmentSplitInfo:
		case commands.LoadCmdReexportDylib:
			var hdr commands.ReExportDylibCmd
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
		// case commands.LoadCmdLazyLoadDylib:
		// case commands.LoadCmdEncryptionInfo:
		case commands.LoadCmdDyldInfo:
		case commands.LoadCmdDyldInfoOnly:
			var info commands.DyldInfoCmd
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
		case commands.LoadCmdLoadUpwardDylib:
			var hdr commands.UpwardDylibCmd
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
		// case commands.LoadCmdVersionMinMacosx:
		// case commands.LoadCmdVersionMinIphoneos:
		case commands.LoadCmdFunctionStarts:
			var led commands.LinkEditDataCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &led); err != nil {
				return nil, err
			}
			l := new(FunctionStarts)
			l.Offset = led.Offset
			l.Size = led.Size
			l.LoadBytes = LoadBytes(cmddat)
			f.Loads[i] = l
		// case commands.LoadCmdDyldEnvironment:
		// case commands.LoadCmdMain:
		case commands.LoadCmdDataInCode:
			var led commands.LinkEditDataCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &led); err != nil {
				return nil, err
			}
			l := new(DataInCode)
			// var e DataInCodeEntry

			l.LoadBytes = LoadBytes(cmddat)
			f.Loads[i] = l
		case commands.LoadCmdSourceVersion:
			var sv commands.SourceVersionCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &sv); err != nil {
				return nil, err
			}
			l := new(SourceVersion)
			l.Version = sv.Version.String()
			l.LoadBytes = LoadBytes(cmddat)
			f.Loads[i] = l
		// case commands.LoadCmdDylibCodeSignDrs:
		// case commands.LoadCmdEncryptionInfo64:
		// case commands.LoadCmdLinkerOption:
		// case commands.LoadCmdLinkerOptimizationHint:
		// case commands.LoadCmdVersionMinTvos:
		// case commands.LoadCmdVersionMinWatchos:
		// case commands.LoadCmdNote:
		case commands.LoadCmdBuildVersion:
			var build commands.BuildVersionCmd
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
			// case commands.LoadCmdDyldExportsTrie:
			// case commands.LoadCmdDyldChainedFixups:
		}
		if s != nil {
			s.sr = io.NewSectionReader(r, int64(s.Offset), int64(s.Filesz))
			s.ReaderAt = s.sr
		}
	}
	return f, nil
}

func (f *File) pushRelocatedSection(sh *Section, r io.ReaderAt, vmaToOffsetMap map[uint64]uint64) error {
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
