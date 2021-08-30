package types

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
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
	ChildHash [BTREE_NODE_HASH_SIZE_MAX]byte
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

// ReadOMapNodeEntry reads a omap node entry from reader
func (n *BTreeNodePhys) ReadOMapNodeEntry(r *bytes.Reader) error {
	var oent OMapNodeEntry

	if n.Flags&BTNODE_FIXED_KV_SIZE == 0 {
		panic("unimplimented")
	} else {
		if err := binary.Read(r, binary.LittleEndian, &oent.Offset); err != nil {
			return fmt.Errorf("failed to read offsets: %v", err)
		}
	}

	pos, _ := r.Seek(0, io.SeekCurrent)

	r.Seek(int64(oent.Offset.Key+n.TableSpace.Len+56), io.SeekStart) // key_hdr

	if err := binary.Read(r, binary.LittleEndian, &oent.Key); err != nil {
		return fmt.Errorf("failed to read omap_key_t: %v", err)
	}

	r.Seek(int64(BLOCK_SIZE-uint64(oent.Offset.Val)-40*uint64(n.Flags&1)), io.SeekStart)

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

// GetNodeEntry returns an FIXME: create type
func (n *BTreeNodePhys) GetNodeEntry(r *bytes.Reader) error {
	var oent OMapNodeEntry

	if n.Flags&BTNODE_FIXED_KV_SIZE == 0 {
		panic("unimplimented")
	} else {
		if err := binary.Read(r, binary.LittleEndian, &oent.Offset); err != nil {
			return fmt.Errorf("failed to read offsets: %v", err)
		}
	}

	pos, _ := r.Seek(0, io.SeekCurrent)

	r.Seek(int64(oent.Offset.Key+n.TableSpace.Len+56), io.SeekStart) // key_hdr

	if err := binary.Read(r, binary.LittleEndian, &oent.Key); err != nil {
		return fmt.Errorf("failed to read omap_key_t: %v", err)
	}

	n.Entries = append(n.Entries, oent)

	r.Seek(pos, io.SeekStart) // reset reader to right after we read the offsets

	return nil
}
