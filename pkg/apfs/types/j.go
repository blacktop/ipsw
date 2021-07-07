package types

type j_obj_types byte // FIXME: what type

const (
	APFS_TYPE_ANY           j_obj_types = 0
	APFS_TYPE_SNAP_METADATA j_obj_types = 1
	APFS_TYPE_EXTENT        j_obj_types = 2
	APFS_TYPE_INODE         j_obj_types = 3
	APFS_TYPE_XATTR         j_obj_types = 4
	APFS_TYPE_SIBLING_LINK  j_obj_types = 5
	APFS_TYPE_DSTREAM_ID    j_obj_types = 6
	APFS_TYPE_CRYPTO_STATE  j_obj_types = 7
	APFS_TYPE_FILE_EXTENT   j_obj_types = 8
	APFS_TYPE_DIR_REC       j_obj_types = 9
	APFS_TYPE_DIR_STATS     j_obj_types = 10
	APFS_TYPE_SNAP_NAME     j_obj_types = 11
	APFS_TYPE_SIBLING_MAP   j_obj_types = 12
	APFS_TYPE_FILE_INFO     j_obj_types = 13

	APFS_TYPE_MAX_VALID j_obj_types = 13
	APFS_TYPE_MAX       j_obj_types = 15

	APFS_TYPE_INVALID j_obj_types = 15
)

type j_obj_kinds byte // FIXME: what type
const (
	APFS_KIND_ANY           j_obj_kinds = 0
	APFS_KIND_NEW           j_obj_kinds = 1
	APFS_KIND_UPDATE        j_obj_kinds = 2
	APFS_KIND_DEAD          j_obj_kinds = 3
	APFS_KIND_UPDATE_RECENT j_obj_kinds = 4

	APFS_KIND_INVALID j_obj_kinds = 255
)

type j_inode_flags uint32 // FIXME: what type
const (
	INODE_IS_APFS_PRIVATE        j_inode_flags = 0x00000001
	INODE_MAINTAIN_DIR_STATS     j_inode_flags = 0x00000002
	INODE_DIR_STATS_ORIGIN       j_inode_flags = 0x00000004
	INODE_PROT_CLASS_EXPLICIT    j_inode_flags = 0x00000008
	INODE_WAS_CLONED             j_inode_flags = 0x00000010
	INODE_FLAG_UNUSED            j_inode_flags = 0x00000020
	INODE_HAS_SECURITY_EA        j_inode_flags = 0x00000040
	INODE_BEING_TRUNCATED        j_inode_flags = 0x00000080
	INODE_HAS_FINDER_INFO        j_inode_flags = 0x00000100
	INODE_IS_SPARSE              j_inode_flags = 0x00000200
	INODE_WAS_EVER_CLONED        j_inode_flags = 0x00000400
	INODE_ACTIVE_FILE_TRIMMED    j_inode_flags = 0x00000800
	INODE_PINNED_TO_MAIN         j_inode_flags = 0x00001000
	INODE_PINNED_TO_TIER2        j_inode_flags = 0x00002000
	INODE_HAS_RSRC_FORK          j_inode_flags = 0x00004000
	INODE_NO_RSRC_FORK           j_inode_flags = 0x00008000
	INODE_ALLOCATION_SPILLEDOVER j_inode_flags = 0x00010000
	INODE_FAST_PROMOTE           j_inode_flags = 0x00020000
	INODE_HAS_UNCOMPRESSED_SIZE  j_inode_flags = 0x00040000
	INODE_IS_PURGEABLE           j_inode_flags = 0x00080000
	INODE_WANTS_TO_BE_PURGEABLE  j_inode_flags = 0x00100000
	INODE_IS_SYNC_ROOT           j_inode_flags = 0x00200000
	INODE_SNAPSHOT_COW_EXEMPTION j_inode_flags = 0x00400000

	INODE_INHERITED_INTERNAL_FLAGS j_inode_flags = (INODE_MAINTAIN_DIR_STATS | INODE_SNAPSHOT_COW_EXEMPTION)

	INODE_CLONED_INTERNAL_FLAGS     j_inode_flags = (INODE_HAS_RSRC_FORK | INODE_NO_RSRC_FORK | INODE_HAS_FINDER_INFO | INODE_SNAPSHOT_COW_EXEMPTION)
	APFS_VALID_INTERNAL_INODE_FLAGS j_inode_flags = (INODE_IS_APFS_PRIVATE | INODE_MAINTAIN_DIR_STATS | INODE_DIR_STATS_ORIGIN | INODE_PROT_CLASS_EXPLICIT | INODE_WAS_CLONED | INODE_HAS_SECURITY_EA | INODE_BEING_TRUNCATED | INODE_HAS_FINDER_INFO | INODE_IS_SPARSE | INODE_WAS_EVER_CLONED | INODE_ACTIVE_FILE_TRIMMED | INODE_PINNED_TO_MAIN | INODE_PINNED_TO_TIER2 | INODE_HAS_RSRC_FORK | INODE_NO_RSRC_FORK | INODE_ALLOCATION_SPILLEDOVER | INODE_FAST_PROMOTE | INODE_HAS_UNCOMPRESSED_SIZE | INODE_IS_PURGEABLE | INODE_WANTS_TO_BE_PURGEABLE | INODE_IS_SYNC_ROOT | INODE_SNAPSHOT_COW_EXEMPTION)
	APFS_INODE_PINNED_MASK          j_inode_flags = (INODE_PINNED_TO_MAIN | INODE_PINNED_TO_TIER2)
)

type j_xattr_flags byte // FIXME: what type
const (
	XATTR_DATA_STREAM       j_xattr_flags = 0x00000001
	XATTR_DATA_EMBEDDED     j_xattr_flags = 0x00000002
	XATTR_FILE_SYSTEM_OWNED j_xattr_flags = 0x00000004
	XATTR_RESERVED_8        j_xattr_flags = 0x00000008
)

type dir_rec_flags byte // FIXME: what type
const (
	DREC_TYPE_MASK dir_rec_flags = 0x000f
	RESERVED_10    dir_rec_flags = 0x0010
)

const (
	/** Inode Numbers **/
	INVALID_INO_NUM       = 0
	ROOT_DIR_PARENT       = 1
	ROOT_DIR_INO_NUM      = 2
	PRIV_DIR_INO_NUM      = 3
	SNAP_DIR_INO_NUM      = 6
	PURGEABLE_DIR_INO_NUM = 7

	MIN_USER_INO_NUM = 16

	UNIFIED_ID_SPACE_MARK = 0x0800000000000000

	/** Extended Attributes Constants **/
	XATTR_MAX_EMBEDDED_SIZE    = 3804 // = 3 Ki + 732
	SYMLINK_EA_NAME            = "com.apple.fs.symlink"
	FIRMLINK_EA_NAME           = "com.apple.fs.firmlink"
	APFS_COW_EXEMPT_COUNT_NAME = "com.apple.fs.cow-exempt-file-count"

	/** File-System Object Constants **/
	OWNING_OBJ_ID_INVALID uint64 = 0xFFFFFFFFFFFFFFFF
	OWNING_OBJ_ID_UNKNOWN uint64 = 0xFFFFFFFFFFFFFFFE

	JOBJ_MAX_KEY_SIZE   = 832
	JOBJ_MAX_VALUE_SIZE = 3808 // = 3 Ki + 736

	MIN_DOC_ID = 3

	/** File Extent Constants **/
	FEXT_CRYPTO_ID_IS_TWEAK = 0x01
)

/** File Modes **/

/**
 * Called `mode_t` in the spec, but this clashes with the GNU `mode_t` on
 * non-Apple platforms, so we use a distinct name for portability.
 */
type apfs_mode_t uint16

const (
	S_IFMT = 0170000

	S_IFIFO  = 0010000
	S_IFCHR  = 0020000
	S_IFDIR  = 0040000
	S_IFBLK  = 0060000
	S_IFREG  = 0100000
	S_IFLNK  = 0120000
	S_IFSOCK = 0140000
	S_IFWHT  = 0160000

	/** Directory Entry File Types **/
	DT_UNKNOWN = 0
	DT_FIFO    = 1
	DT_CHR     = 2
	DT_DIR     = 4
	DT_BLK     = 6
	DT_REG     = 8
	DT_LNK     = 10
	DT_SOCK    = 12
	DT_WHT     = 14
)

// JKeyT is a j_key_t
type JKeyT struct {
	ObjIDAndType uint64
} // __attribute__((packed))

const (
	OBJ_ID_MASK    = 0x0fffffffffffffff
	OBJ_TYPE_MASK  = 0xf000000000000000
	OBJ_TYPE_SHIFT = 60

	SYSTEM_OBJ_ID_MARK = 0x0fffffff00000000
)

type j_inode_key_t struct {
	Hdr JKeyT
} // __attribute__((packed))

type uid_t uint32
type gid_t uint32

type j_inode_val_t struct {
	ParentId      uint64
	PrivateId     uint64
	CreateTime    uint64
	ModTime       uint64
	ChangeTime    uint64
	AccessTime    uint64
	InternalFlags uint64

	// union {
	//     int32_t     nchildren;
	//     int32_t     nlink;
	// };
	NchildrenOrNlink int32

	DefaultProtectionClass cp_key_class_t
	WriteGenerationCounter uint32
	BsdFlags               uint32
	Owner                  uid_t
	Group                  gid_t
	Mode                   apfs_mode_t
	Pad1                   uint16
	UncompressedSize       uint64 // formerly `pad2`
	Xfields                []uint8
} // __attribute__((packed))

type j_drec_key_t struct {
	Hdr     JKeyT
	NameLen uint16 // NOTE: Not `name_len_and_hash` as the spec erroneously says.
	Name    [0]uint8
} // __attribute__((packed))

/**
 * NOTE: The spec says that if a file-system record is of type
 * `APFS_TYPE_DIR_REC`, then the record's key is an instance of `j_drec_key_t`.
 * However, the type `j_drec_hashed_key_t` (seen below) is defined in the spec
 * but not used anywhere in the spec; and upon closer inspection, the keys I
 * have encountered in practice exclusively appear to be instances of
 * `j_drec_hashed_key_t`.
 *
 * As such, either:
 * (a) `j_drec_key_t` has been silently deprecated as of 2019-10-31 and replaced
 *      by `j_drec_hashed_key_t`; or
 * (b) the specific type (`j_drec_key_t` vs. `j_drec_hashed_key_t`) must be
 *      determined by some convoluted means (i.e. case analysis of the data
 *      contained in the key).
 *
 * We assume that (a) is true, i.e. we exclusively use `j_drec_hashed_key_t`.
 */

type j_drec_hashed_key_t struct {
	Hdr            JKeyT
	NameLenAndHash uint32
	Name           [0]uint8
} // __attribute__((packed))

const (
	J_DREC_LEN_MASK   = 0x000003ff
	J_DREC_HASH_MASK  = 0xfffffc00 // Spec incorrectly says `0xfffff400`
	J_DREC_HASH_SHIFT = 10
)

type j_drec_val_t struct {
	FileID    uint64
	DateAdded uint64
	Flags     uint64
	Xfields   []uint8
} // __attribute__((packed))

type j_dir_stats_key_t struct {
	Hdr JKeyT
} // __attribute__((packed))

type j_dir_stats_val_t struct {
	NumChildren uint64
	TotalSize   uint64
	ChainedKey  uint64
	GenCount    uint64
} // __attribute__((packed))

type j_xattr_key_t struct {
	Hdr     JKeyT
	NameLen uint16
	Name    [0]uint8
} // __attribute__((packed))

type j_xattr_val_t struct {
	Flags    uint16
	XdataLen uint16
	Xdata    [0]uint8
} // __attribute__((packed))
