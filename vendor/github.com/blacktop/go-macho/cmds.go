package macho

import (
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"unsafe"

	"github.com/blacktop/go-macho/types"
)

// A Load represents any Mach-O load command.
type Load interface {
	Raw() []byte
	String() string
	Command() types.LoadCmd
	LoadSize(*FileTOC) uint32 // Need the TOC for alignment, sigh.
	Put([]byte, binary.ByteOrder) int
}

// LoadCmdBytes is a command-tagged sequence of bytes.
// This is used for Load Commands that are not (yet)
// interesting to us, and to common up this behavior for
// all those that are.
type LoadCmdBytes struct {
	types.LoadCmd
	LoadBytes
}

func (s LoadCmdBytes) String() string {
	return s.LoadCmd.String() + ": " + s.LoadBytes.String()
}
func (s LoadCmdBytes) Copy() LoadCmdBytes {
	return LoadCmdBytes{LoadCmd: s.LoadCmd, LoadBytes: s.LoadBytes.Copy()}
}

// A LoadBytes is the uninterpreted bytes of a Mach-O load command.
type LoadBytes []byte

func (b LoadBytes) String() string {
	s := "["
	for i, a := range b {
		if i > 0 {
			s += " "
			if len(b) > 48 && i >= 16 {
				s += fmt.Sprintf("... (%d bytes)", len(b))
				break
			}
		}
		s += fmt.Sprintf("%x", a)
	}
	s += "]"
	return s
}
func (b LoadBytes) Raw() []byte                { return b }
func (b LoadBytes) Copy() LoadBytes            { return LoadBytes(append([]byte{}, b...)) }
func (b LoadBytes) LoadSize(t *FileTOC) uint32 { return uint32(len(b)) }

/*******************************************************************************
 * SEGMENT
 *******************************************************************************/

// A SegmentHeader is the header for a Mach-O 32-bit or 64-bit load segment command.
type SegmentHeader struct {
	types.LoadCmd
	Len       uint32
	Name      string
	Addr      uint64
	Memsz     uint64
	Offset    uint64
	Filesz    uint64
	Maxprot   types.VmProtection
	Prot      types.VmProtection
	Nsect     uint32
	Flag      types.SegFlag
	Firstsect uint32
}

func (s *SegmentHeader) String() string {
	return fmt.Sprintf(
		"Seg %s, len=0x%x, addr=0x%x, memsz=0x%x, offset=0x%x, filesz=0x%x, maxprot=0x%x, prot=0x%x, nsect=%d, flag=0x%x, firstsect=%d",
		s.Name, s.Len, s.Addr, s.Memsz, s.Offset, s.Filesz, s.Maxprot, s.Prot, s.Nsect, s.Flag, s.Firstsect)
}

// A Segment represents a Mach-O 32-bit or 64-bit load segment command.
type Segment struct {
	SegmentHeader
	LoadBytes
	// Embed ReaderAt for ReadAt method.
	// Do not embed SectionReader directly
	// to avoid having Read and Seek.
	// If a client wants Read and Seek it must use
	// Open() to avoid fighting over the seek offset
	// with other clients.
	io.ReaderAt
	sr *io.SectionReader
}

func (s *Segment) String() string {
	return fmt.Sprintf(
		"Seg %s, len=0x%x, addr=0x%x, memsz=0x%x, offset=0x%x, filesz=0x%x, maxprot=0x%x, prot=0x%x, nsect=%d, flag=0x%x, firstsect=%d",
		s.Name, s.Len, s.Addr, s.Memsz, s.Offset, s.Filesz, s.Maxprot, s.Prot, s.Nsect, s.Flag, s.Firstsect)
}

func (s *Segment) Put32(b []byte, o binary.ByteOrder) int {
	o.PutUint32(b[0*4:], uint32(s.LoadCmd))
	o.PutUint32(b[1*4:], s.Len)
	putAtMost16Bytes(b[2*4:], s.Name)
	o.PutUint32(b[6*4:], uint32(s.Addr))
	o.PutUint32(b[7*4:], uint32(s.Memsz))
	o.PutUint32(b[8*4:], uint32(s.Offset))
	o.PutUint32(b[9*4:], uint32(s.Filesz))
	o.PutUint32(b[10*4:], uint32(s.Maxprot))
	o.PutUint32(b[11*4:], uint32(s.Prot))
	o.PutUint32(b[12*4:], s.Nsect)
	o.PutUint32(b[13*4:], uint32(s.Flag))
	return 14 * 4
}

func (s *Segment) Put64(b []byte, o binary.ByteOrder) int {
	o.PutUint32(b[0*4:], uint32(s.LoadCmd))
	o.PutUint32(b[1*4:], s.Len)
	putAtMost16Bytes(b[2*4:], s.Name)
	o.PutUint64(b[6*4+0*8:], s.Addr)
	o.PutUint64(b[6*4+1*8:], s.Memsz)
	o.PutUint64(b[6*4+2*8:], s.Offset)
	o.PutUint64(b[6*4+3*8:], s.Filesz)
	o.PutUint32(b[6*4+4*8:], uint32(s.Maxprot))
	o.PutUint32(b[7*4+4*8:], uint32(s.Prot))
	o.PutUint32(b[8*4+4*8:], s.Nsect)
	o.PutUint32(b[9*4+4*8:], uint32(s.Flag))
	return 10*4 + 4*8
}

// Data reads and returns the contents of the segment.
func (s *Segment) Data() ([]byte, error) {
	dat := make([]byte, s.sr.Size())
	n, err := s.sr.ReadAt(dat, 0)
	if n == len(dat) {
		err = nil
	}
	return dat[0:n], err
}

// UncompressedSize returns the size of the segment with its sections uncompressed, ignoring
// its offset within the file.  The returned size is rounded up to the power of two in align.
func (s *Segment) UncompressedSize(t *FileTOC, align uint64) uint64 {
	sz := uint64(0)
	for j := uint32(0); j < s.Nsect; j++ {
		c := t.Sections[j+s.Firstsect]
		sz += c.UncompressedSize()
	}
	return (sz + align - 1) & uint64(-int64(align))
}

func (s *Segment) Copy() *Segment {
	r := &Segment{SegmentHeader: s.SegmentHeader}
	return r
}
func (s *Segment) CopyZeroed() *Segment {
	r := s.Copy()
	r.Filesz = 0
	r.Offset = 0
	r.Nsect = 0
	r.Firstsect = 0
	if s.Command() == types.LcSegment64 {
		r.Len = uint32(unsafe.Sizeof(types.Segment64{}))
	} else {
		r.Len = uint32(unsafe.Sizeof(types.Segment32{}))
	}
	return r
}

func (s *Segment) LoadSize(t *FileTOC) uint32 {
	if s.Command() == types.LcSegment64 {
		return uint32(unsafe.Sizeof(types.Segment64{})) + uint32(s.Nsect)*uint32(unsafe.Sizeof(types.Section64{}))
	}
	return uint32(unsafe.Sizeof(types.Segment32{})) + uint32(s.Nsect)*uint32(unsafe.Sizeof(types.Section32{}))
}

// Open returns a new ReadSeeker reading the segment.
func (s *Segment) Open() io.ReadSeeker { return io.NewSectionReader(s.sr, 0, 1<<63-1) }

/*******************************************************************************
 * SECTION
 *******************************************************************************/

type SectionHeader struct {
	Name      string
	Seg       string
	Addr      uint64
	Size      uint64
	Offset    uint32
	Align     uint32
	Reloff    uint32
	Nreloc    uint32
	Flags     types.SectionFlag
	Reserved1 uint32
	Reserved2 uint32
	Reserved3 uint32 // only present if original was 64-bit
}

// A Reloc represents a Mach-O relocation.
type Reloc struct {
	Addr  uint32
	Value uint32
	// when Scattered == false && Extern == true, Value is the symbol number.
	// when Scattered == false && Extern == false, Value is the section number.
	// when Scattered == true, Value is the value that this reloc refers to.
	Type      uint8
	Len       uint8 // 0=byte, 1=word, 2=long, 3=quad
	Pcrel     bool
	Extern    bool // valid if Scattered == false
	Scattered bool
}

type Section struct {
	SectionHeader
	Relocs []Reloc

	// Embed ReaderAt for ReadAt method.
	// Do not embed SectionReader directly
	// to avoid having Read and Seek.
	// If a client wants Read and Seek it must use
	// Open() to avoid fighting over the seek offset
	// with other clients.
	io.ReaderAt
	sr *io.SectionReader
}

// Data reads and returns the contents of the Mach-O section.
func (s *Section) Data() ([]byte, error) {
	dat := make([]byte, s.sr.Size())
	n, err := s.sr.ReadAt(dat, 0)
	if n == len(dat) {
		err = nil
	}
	return dat[0:n], err
}

func (s *Section) Put32(b []byte, o binary.ByteOrder) int {
	putAtMost16Bytes(b[0:], s.Name)
	putAtMost16Bytes(b[16:], s.Seg)
	o.PutUint32(b[8*4:], uint32(s.Addr))
	o.PutUint32(b[9*4:], uint32(s.Size))
	o.PutUint32(b[10*4:], s.Offset)
	o.PutUint32(b[11*4:], s.Align)
	o.PutUint32(b[12*4:], s.Reloff)
	o.PutUint32(b[13*4:], s.Nreloc)
	o.PutUint32(b[14*4:], uint32(s.Flags))
	o.PutUint32(b[15*4:], s.Reserved1)
	o.PutUint32(b[16*4:], s.Reserved2)
	a := 17 * 4
	return a + s.PutRelocs(b[a:], o)
}

func (s *Section) Put64(b []byte, o binary.ByteOrder) int {
	putAtMost16Bytes(b[0:], s.Name)
	putAtMost16Bytes(b[16:], s.Seg)
	o.PutUint64(b[8*4+0*8:], s.Addr)
	o.PutUint64(b[8*4+1*8:], s.Size)
	o.PutUint32(b[8*4+2*8:], s.Offset)
	o.PutUint32(b[9*4+2*8:], s.Align)
	o.PutUint32(b[10*4+2*8:], s.Reloff)
	o.PutUint32(b[11*4+2*8:], s.Nreloc)
	o.PutUint32(b[12*4+2*8:], uint32(s.Flags))
	o.PutUint32(b[13*4+2*8:], s.Reserved1)
	o.PutUint32(b[14*4+2*8:], s.Reserved2)
	o.PutUint32(b[15*4+2*8:], s.Reserved3)
	a := 16*4 + 2*8
	return a + s.PutRelocs(b[a:], o)
}

func (s *Section) PutRelocs(b []byte, o binary.ByteOrder) int {
	a := 0
	for _, r := range s.Relocs {
		var ri relocInfo
		typ := uint32(r.Type) & (1<<4 - 1)
		len := uint32(r.Len) & (1<<2 - 1)
		pcrel := uint32(0)
		if r.Pcrel {
			pcrel = 1
		}
		ext := uint32(0)
		if r.Extern {
			ext = 1
		}
		switch {
		case r.Scattered:
			ri.Addr = r.Addr&(1<<24-1) | typ<<24 | len<<28 | 1<<31 | pcrel<<30
			ri.Symnum = r.Value
		case o == binary.LittleEndian:
			ri.Addr = r.Addr
			ri.Symnum = r.Value&(1<<24-1) | pcrel<<24 | len<<25 | ext<<27 | typ<<28
		case o == binary.BigEndian:
			ri.Addr = r.Addr
			ri.Symnum = r.Value<<8 | pcrel<<7 | len<<5 | ext<<4 | typ
		}
		o.PutUint32(b, ri.Addr)
		o.PutUint32(b[4:], ri.Symnum)
		a += 8
		b = b[8:]
	}
	return a
}

func (s *Section) UncompressedSize() uint64 {
	if !strings.HasPrefix(s.Name, "__z") {
		return s.Size
	}
	b := make([]byte, 12)
	n, err := s.sr.ReadAt(b, 0)
	if err != nil {
		panic("Malformed object file")
	}
	if n != len(b) {
		return s.Size
	}
	if string(b[:4]) == "ZLIB" {
		return binary.BigEndian.Uint64(b[4:12])
	}
	return s.Size
}

func (s *Section) PutData(b []byte) {
	bb := b[0:s.Size]
	n, err := s.sr.ReadAt(bb, 0)
	if err != nil || uint64(n) != s.Size {
		panic("Malformed object file (ReadAt error)")
	}
}

func (s *Section) PutUncompressedData(b []byte) {
	if strings.HasPrefix(s.Name, "__z") {
		bb := make([]byte, 12)
		n, err := s.sr.ReadAt(bb, 0)
		if err != nil {
			panic("Malformed object file")
		}
		if n == len(bb) && string(bb[:4]) == "ZLIB" {
			size := binary.BigEndian.Uint64(bb[4:12])
			// Decompress starting at b[12:]
			r, err := zlib.NewReader(io.NewSectionReader(s, 12, int64(size)-12))
			if err != nil {
				panic("Malformed object file (zlib.NewReader error)")
			}
			n, err := io.ReadFull(r, b[0:size])
			if err != nil {
				panic("Malformed object file (ReadFull error)")
			}
			if uint64(n) != size {
				panic(fmt.Sprintf("PutUncompressedData, expected to read %d bytes, instead read %d", size, n))
			}
			if err := r.Close(); err != nil {
				panic("Malformed object file (Close error)")
			}
			return
		}
	}
	// Not compressed
	s.PutData(b)
}

func (s *Section) Copy() *Section {
	return &Section{SectionHeader: s.SectionHeader}
}

// Open returns a new ReadSeeker reading the Mach-O section.
func (s *Section) Open() io.ReadSeeker { return io.NewSectionReader(s.sr, 0, 1<<63-1) }

/*******************************************************************************
 * LC_SYMTAB
 *******************************************************************************/

// A Symtab represents a Mach-O symbol table command.
type Symtab struct {
	LoadBytes
	types.SymtabCmd
	Syms []Symbol
}

func (s *Symtab) Put(b []byte, o binary.ByteOrder) int {
	o.PutUint32(b[0*4:], uint32(s.LoadCmd))
	o.PutUint32(b[1*4:], s.Len)
	o.PutUint32(b[2*4:], s.Symoff)
	o.PutUint32(b[3*4:], s.Nsyms)
	o.PutUint32(b[4*4:], s.Stroff)
	o.PutUint32(b[5*4:], s.Strsize)
	return 6 * 4
}

func (s *Symtab) String() string { return fmt.Sprintf("Symtab %#v", s.SymtabCmd) }
func (s *Symtab) Copy() *Symtab {
	return &Symtab{SymtabCmd: s.SymtabCmd, Syms: append([]Symbol{}, s.Syms...)}
}
func (s *Symtab) LoadSize(t *FileTOC) uint32 {
	return uint32(unsafe.Sizeof(types.SymtabCmd{}))
}

// A Symbol is a Mach-O 32-bit or 64-bit symbol table entry.
type Symbol struct {
	Name  string
	Type  types.NLType
	Sect  uint8
	Desc  uint16
	Value uint64
}

/*******************************************************************************
 * LC_SYMSEG
 *******************************************************************************/

// TODO: LC_SYMSEG	0x3	/* link-edit gdb symbol table info (obsolete) */

/*******************************************************************************
 * LC_THREAD
 *******************************************************************************/

// TODO: LC_THREAD	0x4	/* thread */

/*******************************************************************************
 * LC_UNIXTHREAD
 *******************************************************************************/

// A UnixThread represents a Mach-O unix thread command.
type UnixThread struct {
	LoadBytes
	types.UnixThreadCmd
}

// TODO: LC_LOADFVMLIB	0x6	/* load a specified fixed VM shared library */
// TODO: LC_IDFVMLIB	0x7	/* fixed VM shared library identification */
// TODO: LC_IDENT	0x8	/* object identification info (obsolete) */
// TODO: LC_FVMFILE	0x9	/* fixed VM file inclusion (internal use) */
// TODO: LC_PREPAGE      0xa     /* prepage command (internal use) */

/*******************************************************************************
 * LC_DYSYMTAB
 *******************************************************************************/

// A Dysymtab represents a Mach-O dynamic symbol table command.
type Dysymtab struct {
	LoadBytes
	types.DysymtabCmd
	IndirectSyms []uint32 // indices into Symtab.Syms
}

/*******************************************************************************
 * LC_ID_DYLIB, LC_LOAD_{,WEAK_}DYLIB,LC_REEXPORT_DYLIB
 *******************************************************************************/

// A Dylib represents a Mach-O load dynamic library command.
type Dylib struct {
	LoadBytes
	types.DylibCmd
	Name           string
	Time           uint32
	CurrentVersion string
	CompatVersion  string
}

/*******************************************************************************
 * LC_ID_DYLIB
 *******************************************************************************/

// A DylibID represents a Mach-O load dynamic library ident command.
type DylibID Dylib

// TODO: LC_LOAD_DYLINKER 0xe	/* load a dynamic linker */
// TODO: LC_ID_DYLINKER	0xf	/* dynamic linker identification */
// TODO: LC_PREBOUND_DYLIB 0x10	/* modules prebound for a dynamically */
// 				/*  linked shared library */
// TODO: LC_ROUTINES	0x11	/* image routines */

/*******************************************************************************
 * LC_SUB_FRAMEWORK
 *******************************************************************************/

type SubFramework struct {
	LoadBytes
	types.SubFrameworkCmd
	Framework string
}

// TODO: LC_SUB_UMBRELLA 0x13	/* sub umbrella */

/*******************************************************************************
 * LC_SUB_CLIENT
 *******************************************************************************/

// A SubClient is a Mach-O dynamic sub client command.
type SubClient struct {
	LoadBytes
	types.SubClientCmd
	Name string
}

// TODO: LC_SUB_LIBRARY  0x15	/* sub library */
// TODO: LC_TWOLEVEL_HINTS 0x16	/* two-level namespace lookup hints */
// TODO: LC_PREBIND_CKSUM  0x17	/* prebind checksum */

/*******************************************************************************
 * LC_LOAD_WEAK_DYLIB
 *******************************************************************************/

// A WeakDylib represents a Mach-O load weak dynamic library command.
type WeakDylib Dylib

/*******************************************************************************
 * LC_ROUTINES_64
 *******************************************************************************/

type Routines64 struct {
	LoadBytes
	types.Routines64Cmd
	InitAddress uint64
	InitModule  uint64
}

/*******************************************************************************
 * LC_UUID
 *******************************************************************************/

// UUID represents a Mach-O uuid command.
type UUID struct {
	LoadBytes
	types.UUIDCmd
	ID string
}

func (s *UUID) String() string {
	return s.ID
}
func (s *UUID) Copy() *UUID {
	return &UUID{UUIDCmd: s.UUIDCmd}
}
func (s *UUID) LoadSize(t *FileTOC) uint32 {
	return uint32(unsafe.Sizeof(types.UUIDCmd{}))
}
func (s *UUID) Put(b []byte, o binary.ByteOrder) int {
	o.PutUint32(b[0*4:], uint32(s.LoadCmd))
	o.PutUint32(b[1*4:], s.Len)
	copy(b[2*4:], s.UUID[0:])
	return int(s.Len)
}

/*******************************************************************************
 * LC_RPATH
 *******************************************************************************/

// A Rpath represents a Mach-O rpath command.
type Rpath struct {
	LoadBytes
	types.RpathCmd
	Path string
}

/*******************************************************************************
 * LC_CODE_SIGNATURE
 *******************************************************************************/

type CodeSignature struct {
	LoadBytes
	types.CodeSignatureCmd
	Offset uint32
	Size   uint32
}

/*******************************************************************************
 * LC_SEGMENT_SPLIT_INFO
 *******************************************************************************/

type SplitInfo struct {
	LoadBytes
	types.SegmentSplitInfoCmd
	Offset uint32
	Size   uint32
}

/*******************************************************************************
 * LC_REEXPORT_DYLIB
 *******************************************************************************/

type ReExportDylib Dylib

// TODO: LC_LAZY_LOAD_DYLIB 0x20	/* delay load of dylib until first use */
// TODO: LC_ENCRYPTION_INFO 0x21	/* encrypted segment information */

/*******************************************************************************
 * LC_DYLD_INFO
 *******************************************************************************/

// A DyldInfo represents a Mach-O id dyld info command.
type DyldInfo struct {
	LoadBytes
	types.DyldInfoCmd
	RebaseOff    uint32 // file offset to rebase info
	RebaseSize   uint32 //  size of rebase info
	BindOff      uint32 // file offset to binding info
	BindSize     uint32 // size of binding info
	WeakBindOff  uint32 // file offset to weak binding info
	WeakBindSize uint32 //  size of weak binding info
	LazyBindOff  uint32 // file offset to lazy binding info
	LazyBindSize uint32 //  size of lazy binding info
	ExportOff    uint32 // file offset to export info
	ExportSize   uint32 //  size of export info
}

// TODO: LC_DYLD_INFO_ONLY (0x22|LC_REQ_DYLD)	/* compressed dyld information only */

/*******************************************************************************
 * LC_LOAD_UPWARD_DYLIB
 *******************************************************************************/

// A UpwardDylib represents a Mach-O load upward dylib command.
type UpwardDylib Dylib

/*******************************************************************************
 * LC_VERSION_MIN_MACOSX
 *******************************************************************************/

type VersionMinMacosx struct {
	LoadBytes
	types.VersionMinMacOSCmd
	Version string
	Sdk     string
}

/*******************************************************************************
 * LC_VERSION_MIN_IPHONEOS
 *******************************************************************************/

type VersionMinIphoneos struct {
	LoadBytes
	types.VersionMinIPhoneOSCmd
	Version string
	Sdk     string
}

/*******************************************************************************
 * LC_FUNCTION_STARTS
 *******************************************************************************/

// A FunctionStarts represents a Mach-O function starts command.
type FunctionStarts struct {
	LoadBytes
	types.FunctionStartsCmd
	Offset uint32
	Size   uint32
}

// TODO: LC_DYLD_ENVIRONMENT 0x27 /* string for dyld to treat
// 				    like environment variable */
// TODO: LC_MAIN (0x28|LC_REQ_DYLD) /* replacement for LC_UNIXTHREAD */

/*******************************************************************************
 * LC_DATA_IN_CODE
 *******************************************************************************/

// A DataInCode represents a Mach-O data in code command.
type DataInCode struct {
	LoadBytes
	types.DataInCodeCmd
	Entries []types.DataInCodeEntry
}

/*******************************************************************************
 * LC_SOURCE_VERSION
 *******************************************************************************/

// A SourceVersion represents a Mach-O source version.
type SourceVersion struct {
	LoadBytes
	types.SourceVersionCmd
	Version string
}

// TODO: LC_DYLIB_CODE_SIGN_DRS 0x2B /* Code signing DRs copied from linked dylibs */
// TODO: LC_ENCRYPTION_INFO_64 0x2C /* 64-bit encrypted segment information */
// TODO: LC_LINKER_OPTION 0x2D /* linker options in MH_OBJECT files */
// TODO: LC_LINKER_OPTIMIZATION_HINT 0x2E /* optimization hints in MH_OBJECT files */
// TODO: LC_VERSION_MIN_TVOS 0x2F /* build for AppleTV min OS version */
// TODO: LC_VERSION_MIN_WATCHOS 0x30 /* build for Watch min OS version */
// TODO: LC_NOTE 0x31 /* arbitrary data included within a Mach-O file */

/*******************************************************************************
 * LC_BUILD_VERSION
 *******************************************************************************/

// A BuildVersion represents a Mach-O build for platform min OS version.
type BuildVersion struct {
	LoadBytes
	types.BuildVersionCmd
	Platform    string /* platform */
	Minos       string /* X.Y.Z is encoded in nibbles xxxx.yy.zz */
	Sdk         string /* X.Y.Z is encoded in nibbles xxxx.yy.zz */
	NumTools    uint32 /* number of tool entries following this */
	Tool        string
	ToolVersion string
}

// TODO: LC_DYLD_EXPORTS_TRIE (0x33 | LC_REQ_DYLD) /* used with linkedit_data_command, payload is trie */
// TODO: LC_DYLD_CHAINED_FIXUPS (0x34 | LC_REQ_DYLD) /* used with linkedit_data_command */

/*******************************************************************************
 * LC_CODE_SIGNATURE, LC_SEGMENT_SPLIT_INFO,
 * LC_FUNCTION_STARTS, LC_DATA_IN_CODE,
 * LC_DYLIB_CODE_SIGN_DRS,
 * LC_LINKER_OPTIMIZATION_HINT,
 * LC_DYLD_EXPORTS_TRIE, or
 * LC_DYLD_CHAINED_FIXUPS.
 *******************************************************************************/

// A LinkEditData represents a Mach-O linkedit data command.
type LinkEditData struct {
	LoadBytes
	types.LinkEditDataCmd
	Offset uint32
	Size   uint32
}

/*******
HELPERS
********/
func putAtMost16Bytes(b []byte, n string) {
	for i := range n { // at most 16 bytes
		if i == 16 {
			break
		}
		b[i] = n[i]
	}
}

func RoundUp(x, align uint64) uint64 {
	return uint64((x + align - 1) & -align)
}
