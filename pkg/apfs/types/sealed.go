package types

/** `apfs_hash_type_t` --- forward declared for `integrity_meta_phys_t` **/
type apfs_hash_type_t byte // FIXME: type?
const (
	APFS_HASH_INVALID    apfs_hash_type_t = 0
	APFS_HASH_SHA256     apfs_hash_type_t = 0x1
	APFS_HASH_SHA512_256 apfs_hash_type_t = 0x2
	APFS_HASH_SHA384     apfs_hash_type_t = 0x3
	APFS_HASH_SHA512     apfs_hash_type_t = 0x4

	APFS_HASH_MIN apfs_hash_type_t = APFS_HASH_SHA256
	APFS_HASH_MAX apfs_hash_type_t = APFS_HASH_SHA512

	APFS_HASH_DEFAULT apfs_hash_type_t = APFS_HASH_SHA256
)

const (
	APFS_HASH_CCSHA256_SIZE     = 32
	APFS_HASH_CCSHA512_256_SIZE = 32
	APFS_HASH_CCSHA384_SIZE     = 48
	APFS_HASH_CCSHA512_SIZE     = 64

	APFS_HASH_MAX_SIZE = 64
)

type integrity_meta_phys_t struct {
	Obj     ObjPhysT
	Version uint32
	// Fields supported by `version` >= 1
	Flags          uint32
	HashType       apfs_hash_type_t
	RootHashOffset uint32
	BrokenXid      XidT
	// Fields supported by `version` >= 2
	Reserved [9]uint64
} // __attribute__((packed))

/** Integrity Metadata Version Constants **/
const (
	INTEGRITY_META_VERSION_INVALID = 0
	INTEGRITY_META_VERSION_1       = 1
	INTEGRITY_META_VERSION_2       = 2
	INTEGRITY_META_VERSION_HIGHEST = INTEGRITY_META_VERSION_2
)

/** Integrity Metadata Flags **/
const APFS_SEAL_BROKEN = (1 << 0)

type fext_tree_key_t struct {
	PrivateID   uint64
	LogicalAddr uint64
} // __attribute__((packed))

type fext_tree_val_t struct {
	LenAndFlags  uint64
	PhysBlockNum uint64
} // __attribute__((packed))

type j_file_info_key_t struct {
	// Hdr        JKeyT
	InfoAndLba uint64
} // __attribute__((packed))

const (
	J_FILE_INFO_LBA_MASK   = 0x00ffffffffffffff
	J_FILE_INFO_TYPE_MASK  = 0xff00000000000000
	J_FILE_INFO_TYPE_SHIFT = 56
)

/** `j_file_data_hash_val_t` --- forward declared for `j_file_info_val_t` **/

type j_file_data_hash_val_t struct {
	HashedLen uint16
	HashSize  uint8
	Hash      [0]uint8
} // __attribute__((packed))

type j_file_info_val_t struct {
	DHash j_file_data_hash_val_t
} // __attribute__((packed))

/** `j_obj_file_info_type` **/
type j_obj_file_info_type byte // FIXME: type?
const (
	APFS_FILE_INFO_DATA_HASH j_obj_file_info_type = 1
)
