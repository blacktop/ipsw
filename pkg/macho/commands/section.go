package commands

import (
	"fmt"
	"strings"
)

// A Section32 is a 32-bit Mach-O section header.
type Section32 struct {
	Name     [16]byte
	Seg      [16]byte
	Addr     uint32
	Size     uint32
	Offset   uint32
	Align    uint32
	Reloff   uint32
	Nreloc   uint32
	Flags    SectionFlag
	Reserve1 uint32
	Reserve2 uint32
}

// A Section64 is a 64-bit Mach-O section header.
type Section64 struct {
	Name     [16]byte
	Seg      [16]byte
	Addr     uint64
	Size     uint64
	Offset   uint32
	Align    uint32
	Reloff   uint32
	Nreloc   uint32
	Flags    SectionFlag
	Reserve1 uint32
	Reserve2 uint32
	Reserve3 uint32
}

type SectionFlag uint32

const (
	SectionType       SectionFlag = 0x000000ff /* 256 section types */
	SectionAttributes SectionFlag = 0xffffff00 /*  24 section attributes */
)

/*
 * The flags field of a section structure is separated into two parts a section
 * type and section attributes.  The section types are mutually exclusive (it
 * can only have one type) but the section attributes are not (it may have more
 * than one attribute).
 */
const (
	/* Constants for the type of a section */
	Regular         SectionFlag = 0x0 /* regular section */
	Zerofill        SectionFlag = 0x1 /* zero fill on demand section */
	CstringLiterals SectionFlag = 0x2 /* section with only literal C strings*/
	ByteLiterals4   SectionFlag = 0x3 /* section with only 4 byte literals */
	ByteLiterals8   SectionFlag = 0x4 /* section with only 8 byte literals */
	LiteralPointers SectionFlag = 0x5 /* section with only pointers to literals */
	/*
	 * For the two types of symbol pointers sections and the symbol stubs section
	 * they have indirect symbol table entries.  For each of the entries in the
	 * section the indirect symbol table entries, in corresponding order in the
	 * indirect symbol table, start at the index stored in the reserved1 field
	 * of the section structure.  Since the indirect symbol table entries
	 * correspond to the entries in the section the number of indirect symbol table
	 * entries is inferred from the size of the section divided by the size of the
	 * entries in the section.  For symbol pointers sections the size of the entries
	 * in the section is 4 bytes and for symbol stubs sections the byte size of the
	 * stubs is stored in the reserved2 field of the section structure.
	 */
	NonLazySymbolPointers   SectionFlag = 0x6  /* section with only non-lazy symbol pointers */
	LazySymbolPointers      SectionFlag = 0x7  /* section with only lazy symbol pointers */
	SymbolStubs             SectionFlag = 0x8  /* section with only symbol stubs, byte size of stub in the reserved2 field */
	ModInitFuncPointers     SectionFlag = 0x9  /* section with only function pointers for initialization*/
	ModTermFuncPointers     SectionFlag = 0xa  /* section with only function pointers for termination */
	Coalesced               SectionFlag = 0xb  /* section contains symbols that are to be coalesced */
	GbZerofill              SectionFlag = 0xc  /* zero fill on demand section (that can be larger than 4 gigabytes) */
	Interposing             SectionFlag = 0xd  /* section with only pairs of function pointers for interposing */
	ByteLiterals16          SectionFlag = 0xe  /* section with only 16 byte literals */
	DtraceDof               SectionFlag = 0xf  /* section contains DTrace Object Format */
	LazyDylibSymbolPointers SectionFlag = 0x10 /* section with only lazy symbol pointers to lazy loaded dylibs */
	/*
	 * Section types to support thread local variables
	 */
	ThreadLocalRegular              SectionFlag = 0x11 /* template of initial values for TLVs */
	ThreadLocalZerofill             SectionFlag = 0x12 /* template of initial values for TLVs */
	ThreadLocalVariables            SectionFlag = 0x13 /* TLV descriptors */
	ThreadLocalVariablePointers     SectionFlag = 0x14 /* pointers to TLV descriptors */
	ThreadLocalInitFunctionPointers SectionFlag = 0x15 /* functions to call to initialize TLV values */
	InitFuncOffsets                 SectionFlag = 0x16 /* 32-bit offsets to initializers */
)

func (t SectionFlag) IsRegular() bool {
	return (t & SectionType) == Regular
}

func (t SectionFlag) IsZerofill() bool {
	return (t & SectionType) == Zerofill
}

func (t SectionFlag) IsCstringLiterals() bool {
	return (t & SectionType) == CstringLiterals
}

func (t SectionFlag) Is4ByteLiterals() bool {
	return (t & SectionType) == ByteLiterals4
}

func (t SectionFlag) Is8ByteLiterals() bool {
	return (t & SectionType) == ByteLiterals8
}

func (t SectionFlag) IsLiteralPointers() bool {
	return (t & SectionType) == LiteralPointers
}

func (t SectionFlag) IsNonLazySymbolPointers() bool {
	return (t & SectionType) == NonLazySymbolPointers
}

func (t SectionFlag) IsLazySymbolPointers() bool {
	return (t & SectionType) == LazySymbolPointers
}

func (t SectionFlag) IsSymbolStubs() bool {
	return (t & SectionType) == SymbolStubs
}

func (t SectionFlag) IsModInitFuncPointers() bool {
	return (t & SectionType) == ModInitFuncPointers
}

func (t SectionFlag) IsModTermFuncPointers() bool {
	return (t & SectionType) == ModTermFuncPointers
}

func (t SectionFlag) IsCoalesced() bool {
	return (t & SectionType) == Coalesced
}

func (t SectionFlag) IsGbZerofill() bool {
	return (t & SectionType) == GbZerofill
}

func (t SectionFlag) IsInterposing() bool {
	return (t & SectionType) == Interposing
}

func (t SectionFlag) Is16ByteLiterals() bool {
	return (t & SectionType) == ByteLiterals16
}

func (t SectionFlag) IsDtraceDof() bool {
	return (t & SectionType) == DtraceDof
}

func (t SectionFlag) IsLazyDylibSymbolPointers() bool {
	return (t & SectionType) == LazyDylibSymbolPointers
}

func (t SectionFlag) IsThreadLocalRegular() bool {
	return (t & SectionType) == ThreadLocalRegular
}

func (t SectionFlag) IsThreadLocalZerofill() bool {
	return (t & SectionType) == ThreadLocalZerofill
}

func (t SectionFlag) IsThreadLocalVariables() bool {
	return (t & SectionType) == ThreadLocalVariables
}

func (t SectionFlag) IsThreadLocalVariablePointers() bool {
	return (t & SectionType) == ThreadLocalVariablePointers
}

func (t SectionFlag) IsThreadLocalInitFunctionPointers() bool {
	return (t & SectionType) == ThreadLocalInitFunctionPointers
}

func (t SectionFlag) IsInitFuncOffsets() bool {
	return (t & SectionType) == InitFuncOffsets
}

func (f SectionFlag) List() []string {
	var flags []string
	// if f.IsRegular() {
	// 	fStr += "Regular, "
	// }
	if f.IsZerofill() {
		flags = append(flags, "Zerofill")
	}
	if f.IsCstringLiterals() {
		flags = append(flags, "Cstring Literals")
	}
	if f.Is4ByteLiterals() {
		flags = append(flags, "4Byte Literals")
	}
	if f.Is8ByteLiterals() {
		flags = append(flags, "8Byte Literals")
	}
	if f.IsLiteralPointers() {
		flags = append(flags, "Literal Pointers")
	}
	if f.IsNonLazySymbolPointers() {
		flags = append(flags, "NonLazySymbolPointers")
	}
	if f.IsLazySymbolPointers() {
		flags = append(flags, "LazySymbolPointers")
	}
	if f.IsSymbolStubs() {
		flags = append(flags, "SymbolStubs")
	}
	if f.IsModInitFuncPointers() {
		flags = append(flags, "ModInitFuncPointers")
	}
	if f.IsModTermFuncPointers() {
		flags = append(flags, "ModTermFuncPointers")
	}
	if f.IsCoalesced() {
		flags = append(flags, "Coalesced")
	}
	if f.IsGbZerofill() {
		flags = append(flags, "GbZerofill")
	}
	if f.IsInterposing() {
		flags = append(flags, "Interposing")
	}
	if f.Is16ByteLiterals() {
		flags = append(flags, "16Byte Literals")
	}
	if f.IsDtraceDof() {
		flags = append(flags, "Dtrace DOF")
	}
	if f.IsLazyDylibSymbolPointers() {
		flags = append(flags, "LazyDylibSymbolPointers")
	}
	if f.IsThreadLocalRegular() {
		flags = append(flags, "ThreadLocalRegular")
	}
	if f.IsThreadLocalZerofill() {
		flags = append(flags, "ThreadLocalZerofill")
	}
	if f.IsThreadLocalVariables() {
		flags = append(flags, "ThreadLocalVariables")
	}
	if f.IsThreadLocalVariablePointers() {
		flags = append(flags, "ThreadLocalVariablePointers")
	}
	if f.IsThreadLocalInitFunctionPointers() {
		flags = append(flags, "ThreadLocalInitFunctionPointers")
	}
	if f.IsInitFuncOffsets() {
		flags = append(flags, "InitFuncOffsets")
	}
	return flags
}

func (f SectionFlag) String() string {
	var fStr string
	for _, attr := range f.List() {
		fStr += fmt.Sprintf("%s, ", attr)
	}
	return strings.TrimSuffix(fStr, ", ")
}

const (
	/*
	 * Constants for the section attributes part of the flags field of a section
	 * structure.
	 */
	SECTION_ATTRIBUTES_USR SectionFlag = 0xff000000 /* User setable attributes */
	SECTION_ATTRIBUTES_SYS SectionFlag = 0x00ffff00 /* system setable attributes */

	PURE_INSTRUCTIONS   SectionFlag = 0x80000000 /* section contains only true machine instructions */
	NO_TOC              SectionFlag = 0x40000000 /* section contains coalesced symbols that are not to be in a ranlib table of contents */
	STRIP_STATIC_SYMS   SectionFlag = 0x20000000 /* ok to strip static symbols in this section in files with the MH_DYLDLINK flag */
	NO_DEAD_STRIP       SectionFlag = 0x10000000 /* no dead stripping */
	LIVE_SUPPORT        SectionFlag = 0x08000000 /* blocks are live if they reference live blocks */
	SELF_MODIFYING_CODE SectionFlag = 0x04000000 /* Used with i386 code stubs written on by dyld */
	/*
	 * If a segment contains any sections marked with DEBUG then all
	 * sections in that segment must have this attribute.  No section other than
	 * a section marked with this attribute may reference the contents of this
	 * section.  A section with this attribute may contain no symbols and must have
	 * a section type S_REGULAR.  The static linker will not copy section contents
	 * from sections with this attribute into its output file.  These sections
	 * generally contain DWARF debugging info.
	 */
	DEBUG             SectionFlag = 0x02000000 /* a debug section */
	SOME_INSTRUCTIONS SectionFlag = 0x00000400 /* section contains some machine instructions */
	EXT_RELOC         SectionFlag = 0x00000200 /* section has external relocation entries */
	LOC_RELOC         SectionFlag = 0x00000100 /* section has local relocation entries */
)

func (t SectionFlag) GetAttributes() SectionFlag {
	return (t & SectionAttributes)
}

func (t SectionFlag) IsPureInstructions() bool {
	return (t.GetAttributes() & PURE_INSTRUCTIONS) != 0
}
func (t SectionFlag) IsNoToc() bool {
	return (t.GetAttributes() & NO_TOC) != 0
}
func (t SectionFlag) IsStripStaticSyms() bool {
	return (t.GetAttributes() & STRIP_STATIC_SYMS) != 0
}
func (t SectionFlag) IsNoDeadStrip() bool {
	return (t.GetAttributes() & NO_DEAD_STRIP) != 0
}
func (t SectionFlag) IsLiveSupport() bool {
	return (t.GetAttributes() & LIVE_SUPPORT) != 0
}
func (t SectionFlag) IsSelfModifyingCode() bool {
	return (t.GetAttributes() & SELF_MODIFYING_CODE) != 0
}
func (t SectionFlag) IsDebug() bool {
	return (t.GetAttributes() & DEBUG) != 0
}
func (t SectionFlag) IsSomeInstructions() bool {
	return (t.GetAttributes() & SOME_INSTRUCTIONS) != 0
}
func (t SectionFlag) IsExtReloc() bool {
	return (t.GetAttributes() & EXT_RELOC) != 0
}
func (t SectionFlag) IsLocReloc() bool {
	return (t.GetAttributes() & LOC_RELOC) != 0
}

func (f SectionFlag) AttributesList() []string {
	var attrs []string
	if f.IsPureInstructions() {
		attrs = append(attrs, "PureInstructions")
	}
	if f.IsNoToc() {
		attrs = append(attrs, "NoToc")
	}
	if f.IsStripStaticSyms() {
		attrs = append(attrs, "StripStaticSyms")
	}
	if f.IsNoDeadStrip() {
		attrs = append(attrs, "NoDeadStrip")
	}
	if f.IsLiveSupport() {
		attrs = append(attrs, "LiveSupport")
	}
	if f.IsSelfModifyingCode() {
		attrs = append(attrs, "SelfModifyingCode")
	}
	if f.IsDebug() {
		attrs = append(attrs, "Debug")
	}
	if f.IsSomeInstructions() {
		attrs = append(attrs, "SomeInstructions")
	}
	if f.IsExtReloc() {
		attrs = append(attrs, "ExtReloc")
	}
	if f.IsLocReloc() {
		attrs = append(attrs, "LocReloc")
	}
	return attrs
}

func (f SectionFlag) AttributesString() string {
	var aStr string
	for _, attr := range f.AttributesList() {
		aStr += fmt.Sprintf("%s|", attr)
	}
	return strings.TrimSuffix(aStr, "|")
}

// func (ss sections) Print() {
// 	var secFlags string
// 	// var prevSeg string
// 	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
// 	for _, sec := range ss {
// 		secFlags = ""
// 		if !sec.Flags.IsRegular() {
// 			secFlags = fmt.Sprintf("(%s)", sec.Flags)
// 		}
// 		// if !strings.EqualFold(sec.Seg, prevSeg) && len(prevSeg) > 0 {
// 		// 	fmt.Fprintf(w, "\n")
// 		// }
// 		fmt.Fprintf(w, "Mem: 0x%x-0x%x \t %s.%s \t %s \t %s\n", sec.Addr, sec.Addr+sec.Size, sec.Seg, sec.Name, secFlags, sec.Flags.AttributesString())
// 		// prevSeg = sec.Seg
// 	}
// 	w.Flush()
// }
