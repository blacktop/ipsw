package types

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

//go:generate stringer -type=objType,objFlag -output object_string.go

const (
	MAX_CKSUM_SIZE = 8

	// Object Identifier Constants

	OID_NX_SUPERBLOCK  = 1
	OID_INVALID        = 0
	OID_RESERVED_COUNT = 1024

	// Object Type Masks

	OBJECT_TYPE_MASK       = 0x0000ffff
	OBJECT_TYPE_FLAGS_MASK = 0xffff0000

	OBJ_STORAGETYPE_MASK           = 0xc0000000
	OBJECT_TYPE_FLAGS_DEFINED_MASK = 0xf8000000
)

var ErrBadBlockChecksum = errors.New("block failed checksum validation")

type objType uint32
type objFlag uint32

const (
	OBJECT_TYPE_NX_SUPERBLOCK objType = 0x00000001

	OBJECT_TYPE_BTREE      objType = 0x00000002
	OBJECT_TYPE_BTREE_NODE objType = 0x00000003

	OBJECT_TYPE_SPACEMAN            objType = 0x00000005
	OBJECT_TYPE_SPACEMAN_CAB        objType = 0x00000006
	OBJECT_TYPE_SPACEMAN_CIB        objType = 0x00000007
	OBJECT_TYPE_SPACEMAN_BITMAP     objType = 0x00000008
	OBJECT_TYPE_SPACEMAN_FREE_QUEUE objType = 0x00000009

	OBJECT_TYPE_EXTENT_LIST_TREE objType = 0x0000000a
	OBJECT_TYPE_OMAP             objType = 0x0000000b
	OBJECT_TYPE_CHECKPOINT_MAP   objType = 0x0000000c

	OBJECT_TYPE_FS           objType = 0x0000000d
	OBJECT_TYPE_FSTREE       objType = 0x0000000e
	OBJECT_TYPE_BLOCKREFTREE objType = 0x0000000f
	OBJECT_TYPE_SNAPMETATREE objType = 0x00000010

	OBJECT_TYPE_NX_REAPER          objType = 0x00000011
	OBJECT_TYPE_NX_REAP_LIST       objType = 0x00000012
	OBJECT_TYPE_OMAP_SNAPSHOT      objType = 0x00000013
	OBJECT_TYPE_EFI_JUMPSTART      objType = 0x00000014
	OBJECT_TYPE_FUSION_MIDDLE_TREE objType = 0x00000015
	OBJECT_TYPE_NX_FUSION_WBC      objType = 0x00000016
	OBJECT_TYPE_NX_FUSION_WBC_LIST objType = 0x00000017
	OBJECT_TYPE_ER_STATE           objType = 0x00000018

	OBJECT_TYPE_GBITMAP       objType = 0x00000019
	OBJECT_TYPE_GBITMAP_TREE  objType = 0x0000001a
	OBJECT_TYPE_GBITMAP_BLOCK objType = 0x0000001b
	// new in 2020-06-22
	OBJECT_TYPE_ER_RECOVERY_BLOCK objType = 0x0000001c
	OBJECT_TYPE_SNAP_META_EXT     objType = 0x0000001d
	OBJECT_TYPE_INTEGRITY_META    objType = 0x0000001e
	OBJECT_TYPE_FEXT_TREE         objType = 0x0000001f
	OBJECT_TYPE_RESERVED_20       objType = 0x00000020

	OBJECT_TYPE_INVALID objType = 0x00000000
	OBJECT_TYPE_TEST    objType = 0x000000ff

	OBJECT_TYPE_CONTAINER_KEYBAG = `keys`
	OBJECT_TYPE_VOLUME_KEYBAG    = `recs`
	OBJECT_TYPE_MEDIA_KEYBAG     = `mkey`

	/** Object Type Flags **/
	OBJ_VIRTUAL   objFlag = 0x00000000
	OBJ_EPHEMERAL objFlag = 0x80000000
	OBJ_PHYSICAL  objFlag = 0x40000000

	OBJ_NOHEADER      objFlag = 0x20000000
	OBJ_ENCRYPTED     objFlag = 0x10000000
	OBJ_NONPERSISTENT objFlag = 0x08000000
)

type OidT uint64
type XidT uint64

// ObjPhysT is a obj_phys_t object
type ObjPhysT struct {
	Cksum   [MAX_CKSUM_SIZE]byte
	Oid     OidT
	Xid     XidT
	Type    objType
	Subtype objType
}

func (o ObjPhysT) Checksum() uint64 {
	return binary.LittleEndian.Uint64(o.Cksum[:])
}

func (o ObjPhysT) GetType() objType {
	return o.Type & OBJECT_TYPE_MASK
}

func (o ObjPhysT) GetSubType() objType {
	return o.Subtype & OBJECT_TYPE_MASK
}

func (o ObjPhysT) GetFlag() objFlag {
	return objFlag(o.Type & OBJECT_TYPE_FLAGS_MASK)
}

type Obj struct {
	Hdr  ObjPhysT
	Body interface{}

	block
}

func (o Obj) String() string {
	return fmt.Sprintf("%s cksum=%#x, oid=%#x, xid=%#x, sub_type=%s, flag=%s", o.Hdr.GetType(), o.Hdr.Checksum(), o.Hdr.Oid, o.Hdr.Xid, o.Hdr.GetSubType(), o.Hdr.GetFlag())
}

// ReadObj returns a verified object or error if block does not verify
func ReadObj(r *io.SectionReader, blockAddr uint64) (*Obj, error) {

	var err error

	o := &Obj{
		block: block{
			Addr: blockAddr,
			Size: BLOCK_SIZE,
			Data: make([]byte, BLOCK_SIZE),
		},
	}

	r.Seek(int64(blockAddr*BLOCK_SIZE), io.SeekStart)

	if err := binary.Read(r, binary.LittleEndian, &o.Data); err != nil {
		return nil, fmt.Errorf("failed to read %#x sized block data: %v", BLOCK_SIZE, err)
	}

	if !VerifyChecksum(o.Data) {
		return nil, fmt.Errorf("obj_phys_t data block failed checksum validation: %w", ErrBadBlockChecksum)
	}

	o.r = bytes.NewReader(o.Data)

	if err := binary.Read(o.r, binary.LittleEndian, &o.Hdr); err != nil {
		return nil, fmt.Errorf("failed to read obj_phys_t: %v", err)
	}

	switch o.Hdr.GetType() {
	case OBJECT_TYPE_NX_SUPERBLOCK:
		var nxsb NxSuperblock
		if err := binary.Read(o.r, binary.LittleEndian, &nxsb.NxSuperblockT); err != nil {
			return nil, fmt.Errorf("failed to read APFS nx_superblock_t: %v", err)
		}
		if nxsb.Magic.String() != NX_MAGIC {
			return nil, fmt.Errorf("found unexpected nx_superblock_t magic: %s, expected: %s", nxsb.Magic.String(), NX_MAGIC)
		}
		if nxsb.OmapOid > 0 {
			nxsb.OMap, err = ReadObj(r, uint64(nxsb.OmapOid))
			if err != nil {
				return nil, fmt.Errorf("failed to read nx_superblock_t omap at block %#x: %v", nxsb.OmapOid, err)
			}
		}
		o.Body = nxsb
	case OBJECT_TYPE_BTREE:
		fallthrough
	case OBJECT_TYPE_BTREE_NODE:
		var node BTreeNodePhys
		if err := binary.Read(o.r, binary.LittleEndian, &node.BTreeNodePhysT); err != nil {
			return nil, fmt.Errorf("failed to read btree_node_phys_t struct: %v", err)
		}
		if node.Nkeys > 0 {
			switch o.Hdr.GetSubType() {
			case OBJECT_TYPE_OMAP:
				for i := uint32(0); i < node.Nkeys; i++ {
					err := node.ReadOMapNodeEntry(o.r)
					if err != nil {
						return nil, fmt.Errorf("failed to read omap node entry: %v", err)
					}
					// if oent, ok := node.Entries[i].(OMapNodeEntry); ok {
					// 	oent.OMap, err = ReadObj(r, uint64(node.Entries[i].(OMapNodeEntry).Val.Paddr))
					// 	if err != nil {
					// 		return nil, fmt.Errorf("failed to read omap node entry omap")
					// 	}
					// 	node.Entries[i] = oent
					// }
				}
			case OBJECT_TYPE_SPACEMAN_FREE_QUEUE:
				panic("node with OBJECT_TYPE_SPACEMAN_FREE_QUEUE entries is NOT supported yet")
			case OBJECT_TYPE_FEXT_TREE:
				if node.Level > 0 {
					// node.Entries = make([]byte, node.Nkeys)
					// if err := binary.Read(r, binary.LittleEndian, &node.raw); err != nil {
					// 	return nil, fmt.Errorf("failed to read btree node block data: %v", err)
					// }
					panic("node with OBJECT_TYPE_FEXT_TREE entries is NOT supported yet")
				} else {
					panic("node with OBJECT_TYPE_FEXT_TREE entries is NOT supported yet")
				}
			default:
				for i := uint32(0); i < node.Nkeys; i++ {
					err := node.ReadNodeEntry(o.r)
					if err != nil {
						return nil, fmt.Errorf("failed to read node entry: %v", err)
					}
					// if oent, ok := node.Entries[i].(OMapNodeEntry); ok {
					// 	oent.OMap, err = ReadObj(r, uint64(node.Entries[i].(OMapNodeEntry).Val.Paddr))
					// 	if err != nil {
					// 		return nil, fmt.Errorf("failed to read omap node entry omap")
					// 	}
					// 	node.Entries[i] = oent
					// }
				}
			}
		}
		if node.IsRoot() {
			o.r.Seek(-int64(binary.Size(BTreeInfoT{})), io.SeekEnd)
			var info BTreeInfoT
			if err := binary.Read(o.r, binary.LittleEndian, &info); err != nil {
				return nil, fmt.Errorf("failed to read node's btree_info_t data: %v", err)
			}
			node.Info = &info
		}
		o.Body = node
	case OBJECT_TYPE_SPACEMAN:
		fallthrough
	case OBJECT_TYPE_SPACEMAN_CAB:
		fallthrough
	case OBJECT_TYPE_SPACEMAN_CIB:
		fallthrough
	case OBJECT_TYPE_SPACEMAN_BITMAP:
		fallthrough
	case OBJECT_TYPE_SPACEMAN_FREE_QUEUE:
		fallthrough
	case OBJECT_TYPE_EXTENT_LIST_TREE:
		panic("not implimented yet")
	case OBJECT_TYPE_OMAP:
		var omap OMap
		if err := binary.Read(o.r, binary.LittleEndian, &omap.OMapPhysT); err != nil {
			return nil, fmt.Errorf("failed to read omap_phys_t: %v", err)
		}
		if omap.TreeOid > 0 {
			omap.Tree, err = ReadObj(r, uint64(omap.TreeOid))
			if err != nil {
				return nil, fmt.Errorf("failed to read omap_phys_t tree at block %#x: %v", omap.TreeOid, err)
			}
		}
		if omap.SnapshotTreeOid > 0 {
			omap.Tree, err = ReadObj(r, uint64(omap.SnapshotTreeOid))
			if err != nil {
				return nil, fmt.Errorf("failed to read omap_phys_t snapshot_tree at block %#x: %v", omap.SnapshotTreeOid, err)
			}
		}
		o.Body = omap
	case OBJECT_TYPE_CHECKPOINT_MAP:
		var checkpointMap CheckpointMapPhys
		if err := binary.Read(o.r, binary.LittleEndian, &checkpointMap.Hdr); err != nil {
			return nil, fmt.Errorf("failed to read APFS checkpoint_map_phys_t: %v", err)
		}
		checkpointMap.Map = make([]CheckpointMappingT, checkpointMap.Hdr.Count)
		if err := binary.Read(o.r, binary.LittleEndian, &checkpointMap.Map); err != nil {
			return nil, fmt.Errorf("failed to read APFS checkpoint_mapping_t array: %v", err)
		}
		o.Body = checkpointMap
	case OBJECT_TYPE_FS:
		var apsb ApfsSuperblock
		if err := binary.Read(o.r, binary.LittleEndian, &apsb.ApfsSuperblockT); err != nil {
			return nil, fmt.Errorf("failed to read omap_phys_t: %v", err)
		}
		if apsb.Magic.String() != APFS_MAGIC {
			return nil, fmt.Errorf("found unexpected apfs_superblock_t magic: %s, expected: %s", apsb.Magic.String(), APFS_MAGIC)
		}
		if apsb.OmapOid > 0 {
			apsb.OMap, err = ReadObj(r, uint64(apsb.OmapOid))
			if err != nil {
				return nil, fmt.Errorf("failed to read root node of the container object map B-tree at block %#x: %v", apsb.OmapOid, err)
			}
		}
		// if apsb.ExtentrefTreeOid > 0 {
		// 	apsb.ExtentRefTree, err = ReadObj(r, uint64(apsb.ExtentrefTreeOid))
		// 	if err != nil {
		// 		return nil, fmt.Errorf("failed to read root node of the container object map B-tree at block %#x: %v", apsb.ExtentrefTreeOid, err)
		// 	}
		// }
		// if apsb.SnapMetaTreeOid > 0 {
		// 	apsb.SnapMetaTree, err = ReadObj(r, uint64(apsb.SnapMetaTreeOid))
		// 	if err != nil {
		// 		return nil, fmt.Errorf("failed to read root node of the container object map B-tree at block %#x: %v", apsb.SnapMetaTreeOid, err)
		// 	}
		// }
		o.Body = apsb
	case OBJECT_TYPE_FSTREE:
		fallthrough
	case OBJECT_TYPE_BLOCKREFTREE:
		fallthrough
	case OBJECT_TYPE_SNAPMETATREE:
		fallthrough
	case OBJECT_TYPE_NX_REAPER:
		fallthrough
	case OBJECT_TYPE_NX_REAP_LIST:
		fallthrough
	case OBJECT_TYPE_OMAP_SNAPSHOT:
		fallthrough
	case OBJECT_TYPE_EFI_JUMPSTART:
		fallthrough
	case OBJECT_TYPE_FUSION_MIDDLE_TREE:
		fallthrough
	case OBJECT_TYPE_NX_FUSION_WBC:
		fallthrough
	case OBJECT_TYPE_NX_FUSION_WBC_LIST:
		fallthrough
	case OBJECT_TYPE_ER_STATE:
		fallthrough
	case OBJECT_TYPE_GBITMAP:
		fallthrough
	case OBJECT_TYPE_GBITMAP_TREE:
		fallthrough
	case OBJECT_TYPE_GBITMAP_BLOCK:
		fallthrough
	case OBJECT_TYPE_ER_RECOVERY_BLOCK:
		fallthrough
	case OBJECT_TYPE_SNAP_META_EXT:
		fallthrough
	case OBJECT_TYPE_FEXT_TREE:
		fallthrough
	case OBJECT_TYPE_INTEGRITY_META:
		fallthrough
	case OBJECT_TYPE_RESERVED_20:
		panic("not implimented yet")
	case OBJECT_TYPE_INVALID:
		return nil, fmt.Errorf("found %s @ oid=%#x", o.Hdr.GetType(), blockAddr)
	default:
		return nil, fmt.Errorf("unknown obj header type %#x @ oid=%#", o.Hdr.Type, blockAddr)
	}

	return o, nil
}
