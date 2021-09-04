package types

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

const (
	/** B-Tree Table of Contents Constants **/
	BTREE_TOC_ENTRY_INCREMENT  = 8
	BTREE_TOC_ENTRY_MAX_UNUSED = (2 * BTREE_TOC_ENTRY_INCREMENT)

	/** B-Tree Node Constants **/
	BTREE_NODE_SIZE_DEFAULT    = 4096 // = 4 Ki
	BTREE_NODE_MIN_ENTRY_COUNT = 4
)

type btreeInfoFixedFlags uint32

const (
	/** B-Tree Flags **/
	BTREE_UINT64_KEYS       btreeInfoFixedFlags = 0x00000001 // Code that works with the B-tree should enable optimizations to make comparison of keys fast.
	BTREE_SEQUENTIAL_INSERT btreeInfoFixedFlags = 0x00000002 // Code that works with the B-tree should enable optimizations to keep the B-tree compact during sequential insertion of entries.
	BTREE_ALLOW_GHOSTS      btreeInfoFixedFlags = 0x00000004 // The table of contents is allowed to contain keys that have no corresponding value.
	BTREE_EPHEMERAL         btreeInfoFixedFlags = 0x00000008 // The nodes in the B-tree use ephemeral object identifiers to link to child nodes.
	BTREE_PHYSICAL          btreeInfoFixedFlags = 0x00000010 // The nodes in the B-tree use physical object identifiers to link to child nodes.
	BTREE_NONPERSISTENT     btreeInfoFixedFlags = 0x00000020 // The B-tree isnʼt persisted across unmounting.
	BTREE_KV_NONALIGNED     btreeInfoFixedFlags = 0x00000040 // The keys and values in the B-tree arenʼt required to be aligned to eight-byte boundaries.
	BTREE_HASHED            btreeInfoFixedFlags = 0x00000080 // The nonleaf nodes of this B-tree store a hash of their child nodes.
	BTREE_NOHEADER          btreeInfoFixedFlags = 0x00000100 // The nodes of this B-tree are stored without object headers.
)

type btreeNodeFlag uint16

const (
	/** B-Tree Node Flags **/
	BTNODE_ROOT btreeNodeFlag = 0x0001
	BTNODE_LEAF btreeNodeFlag = 0x0002

	BTNODE_FIXED_KV_SIZE btreeNodeFlag = 0x0004
	BTNODE_HASHED        btreeNodeFlag = 0x0008
	BTNODE_NOHEADER      btreeNodeFlag = 0x0010

	BTNODE_CHECK_KOFF_INVAL btreeNodeFlag = 0x8000
)

type nloc_t struct {
	Off uint16
	Len uint16
}

// KVLocT is a kvloc_t struct
type KVLocT struct {
	Key nloc_t
	Val nloc_t
}

// KVOffT is a kvoff_t struct
type KVOffT struct {
	Key uint16
	Val uint16
}

// BTreeInfoFixedT is a btree_info_fixed_t struct
type BTreeInfoFixedT struct {
	Flags    btreeInfoFixedFlags
	NodeSize uint32
	KeySize  uint32
	ValSize  uint32
}

// BTreeInfoT is a btree_info_t struct
type BTreeInfoT struct {
	Fixed      BTreeInfoFixedT
	LongestKey uint32
	LongestVal uint32
	KeyCount   uint64
	NodeCount  uint64
}

const BTREE_NODE_HASH_SIZE_MAX = 64

// BTreeNodeIndexNodeValT is a btn_index_node_val_t
type BTreeNodeIndexNodeValT struct {
	ChildOid  OidT
	ChildHash [32]byte //BTREE_NODE_HASH_SIZE_MAX=64 acc to spec, but in reality appears to be max size of hash type used! 32 seen // FIXME: what?
	// ChildHash [BTREE_NODE_HASH_SIZE_MAX]byte
}

func (v BTreeNodeIndexNodeValT) String() string {
	return fmt.Sprintf("child_oid=%#x, child_hash=%s", v.ChildOid, hex.EncodeToString(v.ChildHash[:]))
}

// OMapEntry is a omap_entry_t struct
// Custom data structure used to store the key and value of an object map entry
// together.
type OMapEntry struct {
	Key OMapKey
	Val OMapVal
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
type JRecT struct {
	KeyLen uint16
	ValLen uint16
	Data   []byte
}

// BTreeNodePhysT is a btree_node_phys_t struct
type BTreeNodePhysT struct {
	// Obj         ObjPhysT
	Flags       btreeNodeFlag
	Level       uint16
	Nkeys       uint32
	TableSpace  nloc_t
	FreeSpace   nloc_t
	KeyFreeList nloc_t
	ValFreeList nloc_t
	// Data        []uint64
}

type block struct {
	Addr uint64
	Size uint64
	Data []byte

	r *bytes.Reader
}

// BTreeNodePhys is a btree_node_phys_t struct with data array
type BTreeNodePhys struct {
	BTreeNodePhysT
	Entries []interface{}
	Parent  *BTreeNodePhys
	Info    *BTreeInfoT

	block
}

func (n *BTreeNodePhys) IsRoot() bool {
	return (n.Flags & BTNODE_ROOT) != 0
}

func (n *BTreeNodePhys) IsLeaf() bool {
	return (n.Flags & BTNODE_LEAF) != 0
}

func (n *BTreeNodePhys) FixedKvSize() bool {
	return (n.Flags & BTNODE_FIXED_KV_SIZE) != 0
}
func (n *BTreeNodePhys) Hashed() bool {
	return (n.Flags & BTNODE_HASHED) != 0
}

// ReadOMapNodeEntry reads a omap node entry from reader
func (n *BTreeNodePhys) ReadOMapNodeEntry(r *bytes.Reader) error {
	var oent OMapNodeEntry
	var keyOffset uint16
	var valOffset uint16

	if n.FixedKvSize() {
		var off KVOffT
		if err := binary.Read(r, binary.LittleEndian, &off); err != nil {
			return fmt.Errorf("failed to read offsets: %v", err)
		}
		keyOffset = off.Key
		valOffset = off.Val
		oent.Offset = off
	} else {
		var off KVLocT
		if err := binary.Read(r, binary.LittleEndian, &off); err != nil {
			return fmt.Errorf("failed to read offsets: %v", err)
		}
		keyOffset = off.Key.Off
		valOffset = off.Val.Off
		oent.Offset = off
	}

	pos, _ := r.Seek(0, io.SeekCurrent)

	r.Seek(int64(keyOffset+n.TableSpace.Len+56), io.SeekStart) // key

	if err := binary.Read(r, binary.LittleEndian, &oent.Key); err != nil {
		return fmt.Errorf("failed to read omap_key_t: %v", err)
	}

	r.Seek(int64(BLOCK_SIZE-uint64(valOffset)-40*uint64(n.Flags&1)), io.SeekStart) // val

	if n.Level > 0 {
		if err := binary.Read(r, binary.LittleEndian, &oent.PAddr); err != nil {
			return fmt.Errorf("failed to read paddr_t: %v", err)
		}
	} else {
		if err := binary.Read(r, binary.LittleEndian, &oent.Val); err != nil {
			return fmt.Errorf("failed to read omap_key_t: %v", err)
		}
	}

	n.Entries = append(n.Entries, oent)

	r.Seek(pos, io.SeekStart) // reset reader to right after we read the offsets

	return nil
}

// ReadNodeEntry reads a node entry from reader
func (n *BTreeNodePhys) ReadNodeEntry(r *bytes.Reader) error {

	var nent NodeEntry
	var keyOffset uint16
	var valOffset uint16

	if n.FixedKvSize() {
		var off KVOffT
		if err := binary.Read(r, binary.LittleEndian, &off); err != nil {
			return fmt.Errorf("failed to read offsets: %v", err)
		}
		keyOffset = off.Key
		valOffset = off.Val
		nent.Offset = off
	} else {
		var off KVLocT
		if err := binary.Read(r, binary.LittleEndian, &off); err != nil {
			return fmt.Errorf("failed to read offsets: %v", err)
		}
		keyOffset = off.Key.Off
		valOffset = off.Val.Off
		nent.Offset = off
	}

	pos, _ := r.Seek(0, io.SeekCurrent)

	r.Seek(int64(keyOffset+n.TableSpace.Len+56), io.SeekStart) // key

	if err := binary.Read(r, binary.LittleEndian, &nent.Hdr); err != nil {
		return fmt.Errorf("failed to read j_key_t: %v", err)
	}

	switch nent.Hdr.GetType() {
	case APFS_TYPE_SNAP_METADATA:
	case APFS_TYPE_EXTENT:
	case APFS_TYPE_INODE:
	case APFS_TYPE_XATTR:
		var k j_xattr_key_t
		if err := binary.Read(r, binary.LittleEndian, &k.NameLen); err != nil {
			return fmt.Errorf("failed to read %T: %v", k, err)
		}
		n := make([]byte, k.NameLen)
		if err := binary.Read(r, binary.LittleEndian, &n); err != nil {
			return fmt.Errorf("failed to read %T: %v", k, err)
		}
		k.Name = strings.Trim(string(n[:]), "\x00")
		nent.Key = k
	case APFS_TYPE_SIBLING_LINK:
		var k SiblingKeyT
		if err := binary.Read(r, binary.LittleEndian, &k); err != nil {
			return fmt.Errorf("failed to read %T: %v", k, err)
		}
		nent.Key = k
	case APFS_TYPE_DSTREAM_ID:
	case APFS_TYPE_CRYPTO_STATE:
	case APFS_TYPE_FILE_EXTENT:
		var k j_file_extent_key_t
		if err := binary.Read(r, binary.LittleEndian, &k); err != nil {
			return fmt.Errorf("failed to read %T: %v", k, err)
		}
		nent.Key = k
	case APFS_TYPE_DIR_REC:
		var k j_drec_hashed_key_t
		if err := binary.Read(r, binary.LittleEndian, &k.NameLenAndHash); err != nil {
			return fmt.Errorf("failed to read %T: %v", k, err)
		}
		n := make([]byte, k.Length())
		if err := binary.Read(r, binary.LittleEndian, &n); err != nil {
			return fmt.Errorf("failed to read %T: %v", k, err)
		}
		k.Name = strings.Trim(string(n[:]), "\x00")
		nent.Key = k
	case APFS_TYPE_DIR_STATS:
	case APFS_TYPE_SNAP_NAME:
		var k j_snap_name_key_t
		if err := binary.Read(r, binary.LittleEndian, &k.NameLen); err != nil {
			return fmt.Errorf("failed to read %T: %v", k, err)
		}
		n := make([]byte, k.NameLen)
		if err := binary.Read(r, binary.LittleEndian, &n); err != nil {
			return fmt.Errorf("failed to read %T: %v", k, err)
		}
		k.Name = strings.Trim(string(n[:]), "\x00")
		nent.Key = k
	case APFS_TYPE_SIBLING_MAP:
	case APFS_TYPE_FILE_INFO:
		var k j_file_info_key_t
		if err := binary.Read(r, binary.LittleEndian, &k); err != nil {
			return fmt.Errorf("failed to read %T: %v", k, err)
		}
		nent.Key = k
	default:
		return fmt.Errorf("got unsupported APFS type %s", nent.Hdr.GetType())
	}

	r.Seek(int64(BLOCK_SIZE-uint64(valOffset)-40*uint64(n.Flags&1)), io.SeekStart) // val

	if n.Level > 0 {
		switch nent.Hdr.GetType() {
		case APFS_TYPE_SNAP_METADATA:
		case APFS_TYPE_SNAP_NAME:
		case APFS_TYPE_EXTENT:
			if err := binary.Read(r, binary.LittleEndian, &nent.PAddr); err != nil {
				return fmt.Errorf("failed to read paddr_t: %v", err)
			}
			// TODO: make sure to read Obj for paddr later
		case APFS_TYPE_INODE:
			fallthrough
		case APFS_TYPE_XATTR:
			fallthrough
		case APFS_TYPE_SIBLING_LINK:
			fallthrough
		case APFS_TYPE_DSTREAM_ID:
			fallthrough
		case APFS_TYPE_CRYPTO_STATE:
			fallthrough
		case APFS_TYPE_FILE_EXTENT:
			fallthrough
		case APFS_TYPE_DIR_REC:
			fallthrough
		case APFS_TYPE_DIR_STATS:
			fallthrough
		case APFS_TYPE_SIBLING_MAP:
			fallthrough
		case APFS_TYPE_FILE_INFO:
			if n.Hashed() {
				var v BTreeNodeIndexNodeValT
				if err := binary.Read(r, binary.LittleEndian, &v); err != nil {
					return fmt.Errorf("failed to read paddr_t: %v", err)
				}
				nent.Val = v
			} else {
				var v uint64
				if err := binary.Read(r, binary.LittleEndian, &v); err != nil {
					return fmt.Errorf("failed to read uint64: %v", err)
				}
				nent.Val = v
			}
		default:
			return fmt.Errorf("got unsupported APFS type %s", nent.Hdr.GetType())
		}
	} else {
		switch nent.Hdr.GetType() {
		case APFS_TYPE_SNAP_METADATA:
			var v j_snap_metadata_val
			if err := binary.Read(r, binary.LittleEndian, &v.j_snap_metadata_val_t); err != nil {
				return fmt.Errorf("failed to read %T: %v", v, err)
			}
			n := make([]byte, v.NameLen)
			if err := binary.Read(r, binary.LittleEndian, &n); err != nil {
				return fmt.Errorf("failed to read %T: %v", v, err)
			}
			v.Name = strings.Trim(string(n[:]), "\x00")
			nent.Val = v
		case APFS_TYPE_EXTENT:
			var v j_phys_ext_val_t
			if err := binary.Read(r, binary.LittleEndian, &v); err != nil {
				return fmt.Errorf("failed to read %T: %v", v, err)
			}
			nent.Val = v
		case APFS_TYPE_INODE:
			var v j_inode_val_t
			if err := binary.Read(r, binary.LittleEndian, &v); err != nil {
				return fmt.Errorf("failed to read %T: %v", v, err)
			}
			nent.Val = v
		case APFS_TYPE_XATTR:
			var v j_xattr_val_t
			if err := binary.Read(r, binary.LittleEndian, &v.Flags); err != nil {
				return fmt.Errorf("failed to read %T: %v", v, err)
			}
			if err := binary.Read(r, binary.LittleEndian, &v.DataLen); err != nil {
				return fmt.Errorf("failed to read %T: %v", v, err)
			}
			if v.Flags.DataEmbedded() {
				v.Data = make([]byte, v.DataLen)
				if err := binary.Read(r, binary.LittleEndian, &v.Data); err != nil {
					return fmt.Errorf("failed to read %T: %v", v, err)
				}
			} else {
				v.Data = uint64(0)
				if err := binary.Read(r, binary.LittleEndian, &v.Data); err != nil {
					return fmt.Errorf("failed to read %T: %v", v, err)
				}
			}
			nent.Val = v
		case APFS_TYPE_SIBLING_LINK:
			var v SiblingValT
			if err := binary.Read(r, binary.LittleEndian, &v.ParentID); err != nil {
				return fmt.Errorf("failed to read %T: %v", v, err)
			}
			if err := binary.Read(r, binary.LittleEndian, &v.NameLen); err != nil {
				return fmt.Errorf("failed to read %T: %v", v, err)
			}
			n := make([]byte, v.NameLen)
			if err := binary.Read(r, binary.LittleEndian, &n); err != nil {
				return fmt.Errorf("failed to read %T: %v", v, err)
			}
			v.Name = strings.Trim(string(n[:]), "\x00")
			nent.Val = v
		case APFS_TYPE_DSTREAM_ID:
			var v j_dstream_id_val_t
			if err := binary.Read(r, binary.LittleEndian, &v); err != nil {
				return fmt.Errorf("failed to read %T: %v", v, err)
			}
			nent.Val = v
		case APFS_TYPE_CRYPTO_STATE:
			var v j_crypto_val_t
			if err := binary.Read(r, binary.LittleEndian, &v.RefCount); err != nil {
				return fmt.Errorf("failed to read %T RefCount: %v", v, err)
			}
			if err := binary.Read(r, binary.LittleEndian, &v.State.wrapped_crypto_state_t); err != nil {
				return fmt.Errorf("failed to read %T wrapped_crypto_state_t: %v", v, err)
			}
			v.State.PersistentKey = make([]byte, v.State.KeyLen)
			if err := binary.Read(r, binary.LittleEndian, &v.State.PersistentKey); err != nil {
				return fmt.Errorf("failed to read %T PersistentKey: %v", v, err)
			}
			nent.Val = v
		case APFS_TYPE_FILE_EXTENT:
			var v j_file_extent_val_t
			if err := binary.Read(r, binary.LittleEndian, &v); err != nil {
				return fmt.Errorf("failed to read %T: %v", v, err)
			}
			nent.Val = v
		case APFS_TYPE_DIR_REC:
			var v j_drec_val_t
			if err := binary.Read(r, binary.LittleEndian, &v); err != nil {
				return fmt.Errorf("failed to read %T: %v", v, err)
			}
			nent.Val = v
		case APFS_TYPE_DIR_STATS:
			var v j_dir_stats_val_t
			if err := binary.Read(r, binary.LittleEndian, &v); err != nil {
				return fmt.Errorf("failed to read %T: %v", v, err)
			}
			nent.Val = v
		case APFS_TYPE_SNAP_NAME:
			var v j_snap_name_val_t
			if err := binary.Read(r, binary.LittleEndian, &v); err != nil {
				return fmt.Errorf("failed to read %T: %v", v, err)
			}
			nent.Val = v
		case APFS_TYPE_SIBLING_MAP:
			var v SiblingMapValT
			if err := binary.Read(r, binary.LittleEndian, &v); err != nil {
				return fmt.Errorf("failed to read %T: %v", v, err)
			}
			nent.Val = v
		case APFS_TYPE_FILE_INFO:
			var v j_file_info_val_t
			if err := binary.Read(r, binary.LittleEndian, &v); err != nil {
				return fmt.Errorf("failed to read %T: %v", v, err)
			}
			nent.Val = v
		default:
			return fmt.Errorf("got unsupported APFS type %s", nent.Hdr.GetType())
		}
	}

	n.Entries = append(n.Entries, nent)

	r.Seek(pos, io.SeekStart) // reset reader to right after we read the offsets

	return nil
}

// GetOMapEntry returns the omap entry for a given oid
func (n *BTreeNodePhys) GetOMapEntry(r *io.SectionReader, oid OidT, maxXid XidT) (*OMapNodeEntry, error) {

	node := n
	var entIdx int

	for {

		for idx, entry := range node.Entries {
			if entry.(OMapNodeEntry).Key.Oid != oid && entry.(OMapNodeEntry).Key.Xid <= maxXid {
				continue
			}
			entIdx = idx
			break
		}

		if node.IsLeaf() {
			if node.Entries[entIdx].(OMapNodeEntry).Key.Oid != oid || node.Entries[entIdx].(OMapNodeEntry).Key.Xid > maxXid {
				return nil, fmt.Errorf("no matching records exist in this B-tree")
			}

			if oentry, ok := node.Entries[entIdx].(OMapNodeEntry); ok {
				return &oentry, nil
			}

			return nil, fmt.Errorf("no matching records exist in this B-tree")
		}

		o, err := ReadObj(r, uint64(node.Entries[entIdx].(OMapNodeEntry).PAddr))
		if err != nil {
			return nil, fmt.Errorf("failed to read child node of entry %d", entIdx)
		}

		if child, ok := o.Body.(BTreeNodePhys); ok {
			node = &child
		}

	}
}
