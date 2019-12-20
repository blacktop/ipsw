package macho

// An Nlist32 is a Mach-O 32-bit symbol table entry.
type Nlist32 struct {
	Name  uint32
	Type  uint8
	Sect  uint8
	Desc  uint16
	Value uint32
}

// An Nlist64 is a Mach-O 64-bit symbol table entry.
type Nlist64 struct {
	Name  uint32
	Type  uint8
	Sect  uint8
	Desc  uint16
	Value uint64
}

type nListType uint8

/*
 * Values for N_TYPE bits of the n_type field.
 */
const (
	N_UNDF nListType = 0x0 /* undefined, n_sect == NO_SECT */
	N_ABS  nListType = 0x2 /* absolute, n_sect == NO_SECT */
	N_SECT nListType = 0xe /* defined in section number n_sect */
	N_PBUD nListType = 0xc /* prebound undefined (defined in a dylib) */
	N_INDR nListType = 0xa /* indirect */
)

type nListDesc uint16

func (d nListDesc) GetCommAlign() nListDesc {
	return (d >> 8) & 0x0f
}

const (
	/* types of references */
	REFERENCE_FLAG_UNDEFINED_NON_LAZY         nListDesc = 0
	REFERENCE_FLAG_UNDEFINED_LAZY             nListDesc = 1
	REFERENCE_FLAG_DEFINED                    nListDesc = 2
	REFERENCE_FLAG_PRIVATE_DEFINED            nListDesc = 3
	REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY nListDesc = 4
	REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY     nListDesc = 5
)

func (d nListDesc) GetLibraryOrdinal() nListDesc {
	return (d >> 8) & 0xff
}

const (
	SELF_LIBRARY_ORDINAL   nListDesc = 0x0
	MAX_LIBRARY_ORDINAL    nListDesc = 0xfd
	DYNAMIC_LOOKUP_ORDINAL nListDesc = 0xfe
	EXECUTABLE_ORDINAL     nListDesc = 0xff
)

const (
	/*
	 * The N_NO_DEAD_STRIP bit of the n_desc field only ever appears in a
	 * relocatable .o file (MH_OBJECT filetype). And is used to indicate to the
	 * static link editor it is never to dead strip the symbol.
	 */
	NO_DEAD_STRIP nListDesc = 0x0020 /* symbol is not to be dead stripped */

	/*
	 * The N_DESC_DISCARDED bit of the n_desc field never appears in linked image.
	 * But is used in very rare cases by the dynamic link editor to mark an in
	 * memory symbol as discared and longer used for linking.
	 */
	DESC_DISCARDED nListDesc = 0x0020 /* symbol is discarded */

	/*
	 * The N_WEAK_REF bit of the n_desc field indicates to the dynamic linker that
	 * the undefined symbol is allowed to be missing and is to have the address of
	 * zero when missing.
	 */
	WEAK_REF nListDesc = 0x0040 /* symbol is weak referenced */

	/*
	 * The N_WEAK_DEF bit of the n_desc field indicates to the static and dynamic
	 * linkers that the symbol definition is weak, allowing a non-weak symbol to
	 * also be used which causes the weak definition to be discared.  Currently this
	 * is only supported for symbols in coalesed sections.
	 */
	WEAK_DEF nListDesc = 0x0080 /* coalesed symbol is a weak definition */

	/*
	 * The N_REF_TO_WEAK bit of the n_desc field indicates to the dynamic linker
	 * that the undefined symbol should be resolved using flat namespace searching.
	 */
	REF_TO_WEAK nListDesc = 0x0080 /* reference to a weak symbol */

	/*
	 * The N_ARM_THUMB_DEF bit of the n_desc field indicates that the symbol is
	 * a defintion of a Thumb function.
	 */
	ARM_THUMB_DEF nListDesc = 0x0008 /* symbol is a Thumb function (ARM) */

	/*
	 * The N_SYMBOL_RESOLVER bit of the n_desc field indicates that the
	 * that the function is actually a resolver function and should
	 * be called to get the address of the real function to use.
	 * This bit is only available in .o files (MH_OBJECT filetype)
	 */
	SYMBOL_RESOLVER nListDesc = 0x0100

	/*
	 * The N_ALT_ENTRY bit of the n_desc field indicates that the
	 * symbol is pinned to the previous content.
	 */
	ALT_ENTRY nListDesc = 0x0200
)
