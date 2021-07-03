package types

const (
	/** B-Tree Flags **/
	BTREE_UINT64_KEYS       = 0x00000001
	BTREE_SEQUENTIAL_INSERT = 0x00000002
	BTREE_ALLOW_GHOSTS      = 0x00000004
	BTREE_EPHEMERAL         = 0x00000008
	BTREE_PHYSICAL          = 0x00000010
	BTREE_NONPERSISTENT     = 0x00000020
	BTREE_KV_NONALIGNED     = 0x00000040
	BTREE_HASHED            = 0x00000080
	BTREE_NOHEADER          = 0x00000100

	/** B-Tree Table of Contents Constants **/
	BTREE_TOC_ENTRY_INCREMENT  = 8
	BTREE_TOC_ENTRY_MAX_UNUSED = (2 * BTREE_TOC_ENTRY_INCREMENT)

	/** B-Tree Node Flags **/
	BTNODE_ROOT = 0x0001
	BTNODE_LEAF = 0x0002

	BTNODE_FIXED_KV_SIZE = 0x0004
	BTNODE_HASHED        = 0x0008
	BTNODE_NOHEADER      = 0x0010

	BTNODE_CHECK_KOFF_INVAL = 0x8000

	/** B-Tree Node Constants **/
	BTREE_NODE_SIZE_DEFAULT    = 4096 // = 4 Ki
	BTREE_NODE_MIN_ENTRY_COUNT = 4
)

type nloc_t struct {
	Off uint16
	Len uint16
}

type btree_node_phys_t struct {
	BtnO           obj_phys_t
	BtnFlags       uint16
	BtnLevel       uint16
	BtnNkeys       uint32
	BtnTableSpace  nloc_t
	BtnFreeSpace   nloc_t
	BtnKeyFreeList nloc_t
	BtnValFreeList nloc_t
	BtnData        []uint64
}

type btree_info_fixed_t struct {
	BtFlags    uint32
	BtNodeSize uint32
	BtKeySize  uint32
	BtValSize  uint32
}

type btree_info_t struct {
	BtFixed      btree_info_fixed_t
	BtLongestKey uint32
	BtLongestVal uint32
	BtKeyCount   uint64
	BtNodeCount  uint64
}

const BTREE_NODE_HASH_SIZE_MAX = 64

type btn_index_node_val_t struct {
	BinvChildOid  oid_t
	BinvChildHash [BTREE_NODE_HASH_SIZE_MAX]byte
}

type kvloc_t struct {
	Key nloc_t
	Val nloc_t
}

type kvoff_t struct {
	Key uint16
	Val uint16
}

/**
 * Custom data structure used to store the key and value of an object map entry
 * together.
 */
type omap_entry_t struct {
	Key omap_key_t
	Val omap_val_t
}

/**
 * Custom data structure used to store a full file-system record (i.e. a single
 * key–value pair from a file-system root tree) alongside each other for easier
 * data access and manipulation.
 *
 * One can make use of an instance of this datatype by determining the strctures
 * contained within its `data` field by appealing to the `obj_id_and_type` field
 * of the `j_key_t` structure for the record, which is guaranteed to exist and
 * start at `data[0]`. That is, a pointer to this instance of `j_key_t` can be
 * obtained with `j_key_t* record_header = record->data`, where `record` is an
 * instance of this type, `j_rec_t`.
 *
 * key_len: Length of the file-system record's key-part, in bytes.
 *
 * val_len: Length of the file-system record's value-part, in bytes.
 *
 * data:    Array of `key_len + val_len` bytes of data, of which,
 *          index `0` through `key_len - 1` (inclusive) contain the
 *          key-part data, and index `key_len` through `key_len + val_len - 1`
 *          (inclusive) contain the value-part data.
 */
type j_rec_t struct {
	KeyLen uint16
	ValLen uint16
	Data   []byte
}
