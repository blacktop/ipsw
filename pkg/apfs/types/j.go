package types

import (
	"fmt"
	"strings"
)

//go:generate stringer -type=j_obj_types,j_obj_kinds,j_inode_flags,dir_rec_flags,apfs_mode_t,dir_ent_file_type -output j_string.go

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

type j_obj_kinds byte

const (
	APFS_KIND_ANY           j_obj_kinds = 0
	APFS_KIND_NEW           j_obj_kinds = 1
	APFS_KIND_UPDATE        j_obj_kinds = 2
	APFS_KIND_DEAD          j_obj_kinds = 3
	APFS_KIND_UPDATE_RECENT j_obj_kinds = 4

	APFS_KIND_INVALID j_obj_kinds = 255
)

type j_inode_flags uint32

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

type j_xattr_flags uint16

const (
	XATTR_DATA_STREAM       j_xattr_flags = 0x00000001
	XATTR_DATA_EMBEDDED     j_xattr_flags = 0x00000002
	XATTR_FILE_SYSTEM_OWNED j_xattr_flags = 0x00000004
	XATTR_RESERVED_8        j_xattr_flags = 0x00000008
)

func (f j_xattr_flags) DataStream() bool {
	return (f & XATTR_DATA_STREAM) != 0
}
func (f j_xattr_flags) DataEmbedded() bool {
	return (f & XATTR_DATA_EMBEDDED) != 0
}
func (f j_xattr_flags) FileSystemOwned() bool {
	return (f & XATTR_FILE_SYSTEM_OWNED) != 0
}
func (f j_xattr_flags) String() string {
	var fout []string
	if f.DataStream() {
		fout = append(fout, "DATA_STREAM")
	}
	if f.DataEmbedded() {
		fout = append(fout, "DATA_EMBEDDED")
	}
	if f.FileSystemOwned() {
		fout = append(fout, "FILE_SYSTEM_OWNED")
	}
	return strings.Join(fout, "|")
}

type dir_rec_flags uint16

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
type dir_ent_file_type uint64

const (
	S_IFMT = 0170000

	S_IFIFO  apfs_mode_t = 0010000
	S_IFCHR  apfs_mode_t = 0020000
	S_IFDIR  apfs_mode_t = 0040000
	S_IFBLK  apfs_mode_t = 0060000
	S_IFREG  apfs_mode_t = 0100000
	S_IFLNK  apfs_mode_t = 0120000
	S_IFSOCK apfs_mode_t = 0140000
	S_IFWHT  apfs_mode_t = 0160000

	/** Directory Entry File Types **/
	DT_UNKNOWN dir_ent_file_type = 0
	DT_FIFO    dir_ent_file_type = 1
	DT_CHR     dir_ent_file_type = 2
	DT_DIR     dir_ent_file_type = 4
	DT_BLK     dir_ent_file_type = 6
	DT_REG     dir_ent_file_type = 8
	DT_LNK     dir_ent_file_type = 10
	DT_SOCK    dir_ent_file_type = 12
	DT_WHT     dir_ent_file_type = 14
)

const (
	OBJ_ID_MASK    = 0x0fffffffffffffff
	OBJ_TYPE_MASK  = 0xf000000000000000
	OBJ_TYPE_SHIFT = 60

	SYSTEM_OBJ_ID_MARK = 0x0fffffff00000000
)

// JKeyT is a j_key_t
type JKeyT struct {
	ObjIDAndType uint64
} // __attribute__((packed))

func (j JKeyT) GetID() uint64 {
	return j.ObjIDAndType & OBJ_ID_MASK
}
func (j JKeyT) GetType() j_obj_types {
	return j_obj_types((j.ObjIDAndType & OBJ_TYPE_MASK) >> OBJ_TYPE_SHIFT)
}

type j_inode_key_t struct {
	Hdr JKeyT
} // __attribute__((packed))

type uid_t uint32
type gid_t uint32

type j_inode_val_t struct {
	ParentId      uint64
	PrivateId     uint64
	CreateTime    EpochTime
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
	// Hdr     JKeyT
	NameLen uint16 // NOTE: Not `name_len_and_hash` as the spec erroneously says.
	Name    string
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
	// Hdr            JKeyT
	NameLenAndHash uint32
	Name           string
} // __attribute__((packed))

const (
	J_DREC_LEN_MASK   uint32 = 0x000003ff
	J_DREC_HASH_MASK  uint32 = 0xfffffc00 // Spec incorrectly says `0xfffff400`
	J_DREC_HASH_SHIFT        = 10
)

func (k j_drec_hashed_key_t) Length() uint32 {
	return k.NameLenAndHash & J_DREC_LEN_MASK
}

func (k j_drec_hashed_key_t) Hash() uint32 {
	return (k.NameLenAndHash & J_DREC_HASH_MASK) >> J_DREC_HASH_SHIFT
}

type j_drec_val_t struct {
	FileID    uint64
	DateAdded EpochTime
	Flags     dir_ent_file_type
	Xfields   []byte
} // __attribute__((packed))

func (val j_drec_val_t) String() string {
	return fmt.Sprintf("file_id=%#x, date_added=%s, flags=%s, xfields=<data>", // TODO: parse xfields
		val.FileID,
		val.DateAdded,
		val.Flags.String(),
	)
}

type j_dir_stats_key_t struct {
	Hdr JKeyT
} // __attribute__((packed))

type j_dir_stats_val_t struct {
	NumChildren uint64
	TotalSize   uint64
	ChainedKey  uint64
	GenCount    uint64
} // __attribute__((packed))

func (val j_dir_stats_val_t) String() string {
	return fmt.Sprintf("num_children=%d, total_size=%d, chained_key=%#x, gen_count=%d",
		val.NumChildren,
		val.TotalSize,
		val.ChainedKey,
		val.GenCount)
}

type j_xattr_key_t struct {
	// Hdr     JKeyT
	NameLen uint16
	Name    string
} // __attribute__((packed))

type j_xattr_val_t struct {
	Flags   j_xattr_flags // The extended attribute recordʼs flags.
	DataLen uint16        // The length of the extended attribute data.
	Data    interface{}   // The extended attribute data or the identifier of a data stream that contains the data.
} // __attribute__((packed))

func (val j_xattr_val_t) String() string {
	var vout []string
	vout = append(vout, fmt.Sprintf("flags=%s", val.Flags.String()))
	if val.Flags.DataEmbedded() {
		vout = append(vout, fmt.Sprintf("data_len=%#x", val.DataLen))
		vout = append(vout, fmt.Sprintf("data=%s", string(val.Data.([]byte)[:]))) // FIXME: don't string print data
	} else {
		vout = append(vout, fmt.Sprintf("dstream_oid=%#x", val.Data.(uint64)))
	}

	return strings.Join(vout, ", ")
}
