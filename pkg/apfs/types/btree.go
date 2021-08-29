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
	Obj         ObjPhysT
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
	// Data    []uint64
	Entries []interface{}
	Info    *BTreeInfoT

	Parent *BTreeNodePhys

	block
}

// ReadBTreeNode creates a NEW BTree node
func ReadBTreeNode(r *io.SectionReader, blockAddr uint64) (*BTreeNodePhys, error) {

	node := &BTreeNodePhys{
		block: block{
			Addr: blockAddr,
			Size: NX_DEFAULT_BLOCK_SIZE,
			Data: make([]byte, NX_DEFAULT_BLOCK_SIZE),
		},
	}

	r.Seek(int64(blockAddr*NX_DEFAULT_BLOCK_SIZE), io.SeekStart)

	if err := binary.Read(r, binary.LittleEndian, &node.Data); err != nil {
		return nil, fmt.Errorf("failed to read btree node block data: %v", err)
	}

	if !VerifyChecksum(node.Data) {
		return nil, fmt.Errorf("btree_node_phys_t data block failed checksum validation")
	}

	node.r = bytes.NewReader(node.Data)

	if err := binary.Read(node.r, binary.LittleEndian, &node.BTreeNodePhysT); err != nil {
		return nil, fmt.Errorf("failed to read btree_node_phys_t struct: %v", err)
	}

	if node.Nkeys > 0 {
		switch node.Obj.Subtype {
		case OBJECT_TYPE_OMAP:
			for i := uint32(0); i < node.Nkeys; i++ {
				err := node.ReadOMapNodeEntry()
				if err != nil {
					return node, fmt.Errorf("failed to read omap node entry")
				}
			}
		case OBJECT_TYPE_SPACEMAN_FREE_QUEUE:
			panic("node with OBJECT_TYPE_SPACEMAN_FREE_QUEUE entries is NOT supported yet")
		case OBJECT_TYPE_FEXT_TREE:
			if node.Level > 0 {
				// node.Entries = make([]byte, node.Nkeys)
				// if err := binary.Read(r, binary.LittleEndian, &node.raw); err != nil {
				// 	return nil, fmt.Errorf("failed to read btree node block data: %v", err)
				// }
			} else {
				panic("node with OBJECT_TYPE_FEXT_TREE entries is NOT supported yet")
			}
		case objType(0): // in case of NOHEADER flag, value will be 0
			panic("node with objType(0) entries is NOT supported yet")
		default:
			panic(fmt.Sprintf("unsupported sub_type: %s", node.Obj.GetSubType()))
		}
	}

	// node.Data = make([]uint64, blockSize-int64(binary.Size(node.BTreeNodePhysT)/binary.Size(uint64(1))))
	// if err := binary.Read(r, binary.LittleEndian, &node.Data); err != nil {
	// 	return nil, fmt.Errorf("failed to read btree_node_phys_t data array: %v", err)
	// }

	if (node.Flags & BTNODE_ROOT) != 0 {
		var err error
		if node.Info, err = node.GetInfo(); err != nil {
			return nil, fmt.Errorf("")
		}

	}

	return node, nil
}

// ReadOMapNodeEntry reads a omap node entry from reader
func (n *BTreeNodePhys) ReadOMapNodeEntry() error {
	var oent OMapNodeEntry

	if err := binary.Read(n.r, binary.LittleEndian, &oent.Offset); err != nil {
		return fmt.Errorf("failed to read offsets: %v", err)
	}

	pos, _ := n.r.Seek(0, io.SeekCurrent)

	n.r.Seek(int64(oent.Offset.Key+n.TableSpace.Len+56), io.SeekStart)

	if err := binary.Read(n.r, binary.LittleEndian, &oent.Key); err != nil {
		return fmt.Errorf("failed to read omap_key_t: %v", err)
	}

	n.r.Seek(int64(NX_DEFAULT_BLOCK_SIZE-oent.Offset.Val-40*uint16(n.Flags&1)), io.SeekStart)

	if n.Level > 0 {
		panic("level > 0 not implimented yet")
	} else {
		if err := binary.Read(n.r, binary.LittleEndian, &oent.Val); err != nil {
			return fmt.Errorf("failed to read omap_key_t: %v", err)
		}
	}

	n.Entries = append(n.Entries, oent)

	n.r.Seek(pos, io.SeekEnd) // reset reader to right after we read the offsets

	return nil
}

// GetBlockSize returns a nodes block size
func (n *BTreeNodePhys) GetBlockSize() int64 {
	return int64(n.block.Size)
}

// GetBytes returns a byte array from the node block
func (n *BTreeNodePhys) GetBytes(offset int64, length uint16) ([]byte, error) {
	n.r.Seek(offset, io.SeekStart)
	dat := make([]byte, length)
	if err := binary.Read(n.r, binary.LittleEndian, &dat); err != nil {
		return nil, fmt.Errorf("failed to read data from block: %v", err)
	}
	return dat, nil
}

// GetInfo returns a nodes B-tree info
func (n *BTreeNodePhys) GetInfo() (*BTreeInfoT, error) {
	n.r.Seek(-int64(binary.Size(BTreeInfoT{})), io.SeekEnd)
	var btInfo BTreeInfoT
	if err := binary.Read(n.r, binary.LittleEndian, &btInfo); err != nil {
		return nil, fmt.Errorf("failed to read node's btree_info_t data: %v", err)
	}
	n.r.Seek(0, io.SeekStart) // reset reader
	return &btInfo, nil
}

// GetOid returns a oid_t
func (n *BTreeNodePhys) GetOid(offset int64) (*OidT, error) {
	n.r.Seek(offset, io.SeekStart)
	var o OidT
	if err := binary.Read(n.r, binary.LittleEndian, &o); err != nil {
		return nil, fmt.Errorf("failed to read kvoff_t data: %v", err)
	}
	return &o, nil
}

// GetTocKVOffEntry returns a kvoff_t
func (n *BTreeNodePhys) GetTocKVOffEntry(offset int64) (*KVOffT, error) {
	n.r.Seek(offset, io.SeekStart)
	var tocEntry KVOffT
	if err := binary.Read(n.r, binary.LittleEndian, &tocEntry); err != nil {
		return nil, fmt.Errorf("failed to read kvoff_t data: %v", err)
	}
	return &tocEntry, nil
}

// GetTocKVLocEntry returns a kvoff_t
func (n *BTreeNodePhys) GetTocKVLocEntry(offset int64) (*KVLocT, error) {
	n.r.Seek(offset, io.SeekStart)
	var tocEntry KVLocT
	if err := binary.Read(n.r, binary.LittleEndian, &tocEntry); err != nil {
		return nil, fmt.Errorf("failed to read kvoff_t data: %v", err)
	}
	return &tocEntry, nil
}

func (n *BTreeNodePhys) GetTocKVOffEntries(offset int, length uint16) ([]KVOffT, error) {
	entries := make([]KVOffT, length/uint16(binary.Size(KVOffT{})))
	n.r.Seek(int64(offset), io.SeekStart)
	if err := binary.Read(n.r, binary.LittleEndian, entries); err != nil {
		return nil, fmt.Errorf("failed to read kvoff_t data: %v", err)
	}
	return entries, nil
}

func (n *BTreeNodePhys) GetTocKVLocEntries(offset int64, length uint16) ([]KVLocT, error) {
	entries := make([]KVLocT, length/uint16(binary.Size(KVLocT{})))
	n.r.Seek(offset, io.SeekStart)
	if err := binary.Read(n.r, binary.LittleEndian, entries); err != nil {
		return nil, fmt.Errorf("failed to read kvloc_t data: %v", err)
	}
	return entries, nil
}

// GetOMapKey returns an omap_key_t
func (n *BTreeNodePhys) GetOMapKey(offset int64) (*OMapKey, error) {
	n.r.Seek(offset, io.SeekStart)
	var key OMapKey
	if err := binary.Read(n.r, binary.LittleEndian, &key); err != nil {
		return nil, fmt.Errorf("failed to read omap_key_t data: %v", err)
	}
	return &key, nil
}

func (n *BTreeNodePhys) GetOMapKeys(offset int64, count uint64) ([]OMapKey, error) {
	keys := make([]OMapKey, count)
	n.r.Seek(offset, io.SeekStart)
	if err := binary.Read(n.r, binary.LittleEndian, keys); err != nil {
		return nil, fmt.Errorf("failed to read omap keys: %v", err)
	}
	return keys, nil
}

// GetJKey returns an j_key_t
func (n *BTreeNodePhys) GetJKey(offset int64) (*JKeyT, error) {
	n.r.Seek(offset, io.SeekStart)
	var key JKeyT
	if err := binary.Read(n.r, binary.LittleEndian, &key); err != nil {
		return nil, fmt.Errorf("failed to read j_key_t data: %v", err)
	}
	return &key, nil
}

func (n *BTreeNodePhys) GetJKeys(offset int64, count uint64) ([]JKeyT, error) {
	keys := make([]JKeyT, count)
	n.r.Seek(offset, io.SeekStart)
	if err := binary.Read(n.r, binary.LittleEndian, keys); err != nil {
		return nil, fmt.Errorf("failed to read J keys: %v", err)
	}
	return keys, nil
}

// GetOMapEntry returns an omap_entry_t
func (n *BTreeNodePhys) GetOMapEntry(keyOff, valOff int64, oid OidT, maxXid XidT) (*OMapEntry, error) {
	omapEntry := OMapEntry{}

	n.r.Seek(keyOff, io.SeekStart)

	if err := binary.Read(n.r, binary.LittleEndian, &omapEntry.Key); err != nil {
		return nil, fmt.Errorf("failed to read omap_key_t data: %v", err)
	}

	if omapEntry.Key.Oid != oid || omapEntry.Key.Xid > maxXid {
		return nil, fmt.Errorf("key.Oid != oid || key.Xid > maxXid")
	}

	n.r.Seek(valOff, io.SeekStart)

	if err := binary.Read(n.r, binary.LittleEndian, &omapEntry.Val); err != nil {
		return nil, fmt.Errorf("failed to read omap_val_t data: %v", err)
	}

	return &omapEntry, nil
}

// GetChildNode returns a node's child node
func (n *BTreeNodePhys) GetChildNode(r io.ReadSeekCloser, offset int64) (*BTreeNodePhys, error) {
	n.r.Seek(offset, io.SeekStart)
	var childNodeAddr uint64
	if err := binary.Read(n.r, binary.LittleEndian, &childNodeAddr); err != nil {
		return nil, fmt.Errorf("failed to read child_node addr: %v", err)
	}
	// return ReadBTreeNode(n.r, childNodeAddr) // FIXME: do we still need this?
	return nil, nil
}

// ValidChecksum returns true if checksum is valid
func (n *BTreeNodePhys) ValidChecksum() bool {
	return VerifyChecksum(n.Data)
}
