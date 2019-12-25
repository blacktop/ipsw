package macho

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
	/*
	 * The flags field of a section structure is separated into two parts a section
	 * type and section attributes.  The section types are mutually exclusive (it
	 * can only have one type) but the section attributes are not (it may have more
	 * than one attribute).
	 */
	SECTION_TYPE SectionFlag = 0x000000ff /* 256 section types */
	/* Constants for the type of a section */
	S_REGULAR          SectionFlag = 0x0 /* regular section */
	S_ZEROFILL         SectionFlag = 0x1 /* zero fill on demand section */
	S_CSTRING_LITERALS SectionFlag = 0x2 /* section with only literal C strings*/
	S_4BYTE_LITERALS   SectionFlag = 0x3 /* section with only 4 byte literals */
	S_8BYTE_LITERALS   SectionFlag = 0x4 /* section with only 8 byte literals */
	S_LITERAL_POINTERS SectionFlag = 0x5 /* section with only pointers to literals */
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
	S_NON_LAZY_SYMBOL_POINTERS   SectionFlag = 0x6  /* section with only non-lazy symbol pointers */
	S_LAZY_SYMBOL_POINTERS       SectionFlag = 0x7  /* section with only lazy symbol pointers */
	S_SYMBOL_STUBS               SectionFlag = 0x8  /* section with only symbol stubs, byte size of stub in the reserved2 field */
	S_MOD_INIT_FUNC_POINTERS     SectionFlag = 0x9  /* section with only function pointers for initialization*/
	S_MOD_TERM_FUNC_POINTERS     SectionFlag = 0xa  /* section with only function pointers for termination */
	S_COALESCED                  SectionFlag = 0xb  /* section contains symbols that are to be coalesced */
	S_GB_ZEROFILL                SectionFlag = 0xc  /* zero fill on demand section (that can be larger than 4 gigabytes) */
	S_INTERPOSING                SectionFlag = 0xd  /* section with only pairs of function pointers for interposing */
	S_16BYTE_LITERALS            SectionFlag = 0xe  /* section with only 16 byte literals */
	S_DTRACE_DOF                 SectionFlag = 0xf  /* section contains DTrace Object Format */
	S_LAZY_DYLIB_SYMBOL_POINTERS SectionFlag = 0x10 /* section with only lazy symbol pointers to lazy loaded dylibs */
	/*
	 * Section types to support thread local variables
	 */
	S_THREAD_LOCAL_REGULAR                SectionFlag = 0x11 /* template of initial values for TLVs */
	S_THREAD_LOCAL_ZEROFILL               SectionFlag = 0x12 /* template of initial values for TLVs */
	S_THREAD_LOCAL_VARIABLES              SectionFlag = 0x13 /* TLV descriptors */
	S_THREAD_LOCAL_VARIABLE_POINTERS      SectionFlag = 0x14 /* pointers to TLV descriptors */
	S_THREAD_LOCAL_INIT_FUNCTION_POINTERS SectionFlag = 0x15 /* functions to call to initialize TLV values */
	S_INIT_FUNC_OFFSETS                   SectionFlag = 0x16 /* 32-bit offsets to initializers */
)

func (t SectionFlag) IsRegular() bool {
	return (t & SECTION_TYPE) == S_REGULAR
}

func (t SectionFlag) IsZerofill() bool {
	return (t & SECTION_TYPE) == S_ZEROFILL
}

func (t SectionFlag) IsCstringLiterals() bool {
	return (t & SECTION_TYPE) == S_CSTRING_LITERALS
}

func (t SectionFlag) Is_4ByteLiterals() bool {
	return (t & SECTION_TYPE) == S_4BYTE_LITERALS
}

func (t SectionFlag) Is_8ByteLiterals() bool {
	return (t & SECTION_TYPE) == S_8BYTE_LITERALS
}

func (t SectionFlag) IsLiteralPointers() bool {
	return (t & SECTION_TYPE) == S_LITERAL_POINTERS
}

func (t SectionFlag) IsNonLazySymbolPointers() bool {
	return (t & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS
}

func (t SectionFlag) IsLazySymbolPointers() bool {
	return (t & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS
}

func (t SectionFlag) IsSymbolStubs() bool {
	return (t & SECTION_TYPE) == S_SYMBOL_STUBS
}

func (t SectionFlag) IsModInitFuncPointers() bool {
	return (t & SECTION_TYPE) == S_MOD_INIT_FUNC_POINTERS
}

func (t SectionFlag) IsModTermFuncPointers() bool {
	return (t & SECTION_TYPE) == S_MOD_TERM_FUNC_POINTERS
}

func (t SectionFlag) IsCoalesced() bool {
	return (t & SECTION_TYPE) == S_COALESCED
}

func (t SectionFlag) IsGbZerofill() bool {
	return (t & SECTION_TYPE) == S_GB_ZEROFILL
}

func (t SectionFlag) IsInterposing() bool {
	return (t & SECTION_TYPE) == S_INTERPOSING
}

func (t SectionFlag) Is_16ByteLiterals() bool {
	return (t & SECTION_TYPE) == S_16BYTE_LITERALS
}

func (t SectionFlag) IsDtraceDof() bool {
	return (t & SECTION_TYPE) == S_DTRACE_DOF
}

func (t SectionFlag) IsLazyDylibSymbolPointers() bool {
	return (t & SECTION_TYPE) == S_LAZY_DYLIB_SYMBOL_POINTERS
}

func (t SectionFlag) IsThreadLocalRegular() bool {
	return (t & SECTION_TYPE) == S_THREAD_LOCAL_REGULAR
}

func (t SectionFlag) IsThreadLocalZerofill() bool {
	return (t & SECTION_TYPE) == S_THREAD_LOCAL_ZEROFILL
}

func (t SectionFlag) IsThreadLocalVariables() bool {
	return (t & SECTION_TYPE) == S_THREAD_LOCAL_VARIABLES
}

func (t SectionFlag) IsThreadLocalVariablePointers() bool {
	return (t & SECTION_TYPE) == S_THREAD_LOCAL_VARIABLE_POINTERS
}

func (t SectionFlag) IsThreadLocalInitFunctionPointers() bool {
	return (t & SECTION_TYPE) == S_THREAD_LOCAL_INIT_FUNCTION_POINTERS
}

func (t SectionFlag) IsInitFuncOffsets() bool {
	return (t & SECTION_TYPE) == S_INIT_FUNC_OFFSETS
}

const (
	SECTION_ATTRIBUTES SectionFlag = 0xffffff00 /*  24 section attributes */
	/*
	 * Constants for the section attributes part of the flags field of a section
	 * structure.
	 */
	SECTION_ATTRIBUTES_USR     SectionFlag = 0xff000000 /* User setable attributes */
	S_ATTR_PURE_INSTRUCTIONS   SectionFlag = 0x80000000 /* section contains only true machine instructions */
	S_ATTR_NO_TOC              SectionFlag = 0x40000000 /* section contains coalesced symbols that are not to be in a ranlib table of contents */
	S_ATTR_STRIP_STATIC_SYMS   SectionFlag = 0x20000000 /* ok to strip static symbols in this section in files with the MH_DYLDLINK flag */
	S_ATTR_NO_DEAD_STRIP       SectionFlag = 0x10000000 /* no dead stripping */
	S_ATTR_LIVE_SUPPORT        SectionFlag = 0x08000000 /* blocks are live if they reference live blocks */
	S_ATTR_SELF_MODIFYING_CODE SectionFlag = 0x04000000 /* Used with i386 code stubs written on by dyld */
	/*
	 * If a segment contains any sections marked with S_ATTR_DEBUG then all
	 * sections in that segment must have this attribute.  No section other than
	 * a section marked with this attribute may reference the contents of this
	 * section.  A section with this attribute may contain no symbols and must have
	 * a section type S_REGULAR.  The static linker will not copy section contents
	 * from sections with this attribute into its output file.  These sections
	 * generally contain DWARF debugging info.
	 */
	S_ATTR_DEBUG             SectionFlag = 0x02000000 /* a debug section */
	SECTION_ATTRIBUTES_SYS   SectionFlag = 0x00ffff00 /* system setable attributes */
	S_ATTR_SOME_INSTRUCTIONS SectionFlag = 0x00000400 /* section contains some machine instructions */
	S_ATTR_EXT_RELOC         SectionFlag = 0x00000200 /* section has external relocation entries */
	S_ATTR_LOC_RELOC         SectionFlag = 0x00000100 /* section has local relocation entries */
)
