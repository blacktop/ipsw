package types

const (
	// Magic numbers used by Code Signing
	CSMAGIC_REQUIREMENT        = 0xfade0c00 // single Requirement blob
	CSMAGIC_REQUIREMENTS       = 0xfade0c01 // Requirements vector (internal requirements)
	CSMAGIC_CODEDIRECTORY      = 0xfade0c02 // CodeDirectory blob
	CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0 // embedded form of signature data
	CSMAGIC_DETACHED_SIGNATURE = 0xfade0cc1 // multi-arch collection of embedded signatures
	CSMAGIC_BLOBWRAPPER        = 0xfade0b01 // used for the cms blob
)

const (
	CS_PAGE_SIZE = 4096

	CS_HASHTYPE_SHA1             = 1
	CS_HASHTYPE_SHA256           = 2
	CS_HASHTYPE_SHA256_TRUNCATED = 3
	CS_HASHTYPE_SHA384           = 4

	CS_HASH_SIZE_SHA1             = 20
	CS_HASH_SIZE_SHA256           = 32
	CS_HASH_SIZE_SHA256_TRUNCATED = 20

	CSSLOT_CODEDIRECTORY                 = 0
	CSSLOT_INFOSLOT                      = 1
	CSSLOT_REQUIREMENTS                  = 2
	CSSLOT_RESOURCEDIR                   = 3
	CSSLOT_APPLICATION                   = 4
	CSSLOT_ENTITLEMENTS                  = 5
	CSSLOT_ALTERNATE_CODEDIRECTORIES     = 0x1000
	CSSLOT_ALTERNATE_CODEDIRECTORY_MAX   = 5
	CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT = CSSLOT_ALTERNATE_CODEDIRECTORIES + CSSLOT_ALTERNATE_CODEDIRECTORY_MAX
	CSSLOT_CMS_SIGNATURE                 = 0x10000

	kSecCodeSignatureAdhoc = 2
)

const CS_REQUIRE_LV = 0x0002000 // require library validation

// Structure of a SuperBlob
type CsBlobIndex struct {
	Type   uint32 // type of entry
	Offset uint32 // offset of entry
}

type CsSuperBlob struct {
	Magic  uint32 // magic number
	Length uint32 // total length of SuperBlob
	Count  uint32 // number of index entries following
	// Index  []CsBlobIndex // (count) entries
	// followed by Blobs in no particular order as indicated by offsets in index
}

// type CsSuperBlob struct {
// 	Magic  uint32        // magic number
// 	Length uint32        // total length of SuperBlob
// 	Count  uint32        // number of index entries following
// 	Index  []CsBlobIndex // (count) entries
// 	// followed by Blobs in no particular order as indicated by offsets in index
// }

// C form of a CodeDirectory.
type CsCodeDirectory struct {
	Magic         uint32 // magic number (CSMAGIC_CODEDIRECTORY) */
	Length        uint32 // total length of CodeDirectory blob
	Version       uint32 // compatibility version
	Flags         uint32 // setup and mode flags
	HashOffset    uint32 // offset of hash slot element at index zero
	IdentOffset   uint32 // offset of identifier string
	NSpecialSlots uint32 // number of special hash slots
	NCodeSlots    uint32 // number of ordinary (code) hash slots
	CodeLimit     uint32 // limit to main image signature range
	HashSize      uint8  // size of each hash in bytes
	HashType      uint8  // type of hash (cdHashType* constants)
	Platform      uint8  // platform identifier zero if not platform binary
	PageSize      uint8  // log2(page size in bytes) 0 => infinite
	Spare2        uint32 // unused (must be zero)

	EndEarliest [0]uint8

	/* Version 0x20100 */
	ScatterOffset  uint32 /* offset of optional scatter vector */
	EndWithScatter [0]uint8

	/* Version 0x20200 */
	TeamOffset  uint32 /* offset of optional team identifier */
	EndWithTeam [0]uint8

	/* Version 0x20300 */
	Spare3             uint32 /* unused (must be zero) */
	CodeLimit64        uint64 /* limit to main image signature range, 64 bits */
	EndWithCodeLimit64 [0]uint8

	/* Version 0x20400 */
	ExecSegBase    uint64 /* offset of executable segment */
	ExecSegLimit   uint64 /* limit of executable segment */
	ExecSegFlags   uint64 /* exec segment flags */
	EndWithExecSeg [0]uint8

	/* followed by dynamic content as located by offset fields above */
}

type CsBlob struct {
	Magic  uint32 // magic number
	Length uint32 // total length of blob
}

type CsRequirementsBlob struct {
	Magic  uint32 // magic number
	Length uint32 // total length of blob
	Data   uint32 // zero for dyld shared cache
}

type CsScatter struct {
	Count        uint32 // number of pages zero for sentinel (only)
	Base         uint32 // first page number
	TargetOffset uint64 // byte offset in target
	Spare        uint64 // reserved (must be zero)
}
