package types

import (
	"encoding/binary"
	"fmt"
)

//go:generate stringer -type=objType -output object_string.go

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

type objType uint32

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
	OBJ_VIRTUAL   objType = 0x00000000
	OBJ_EPHEMERAL objType = 0x80000000
	OBJ_PHYSICAL  objType = 0x40000000

	OBJ_NOHEADER      objType = 0x20000000
	OBJ_ENCRYPTED     objType = 0x10000000
	OBJ_NONPERSISTENT objType = 0x08000000
)

type OidT uint64
type XidT uint64

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

func (o ObjPhysT) GetFlag() objType {
	return o.Type & OBJECT_TYPE_FLAGS_MASK
}

type Obj struct {
	Hdr  ObjPhysT
	Body interface{}
}

func (o Obj) String() string {
	return fmt.Sprintf("%s cksum=%#x, oid=%#x, xid=%#x, sub_type=%x", o.Hdr.GetType(), o.Hdr.Checksum(), o.Hdr.Oid, o.Hdr.Xid, o.Hdr.GetSubType())
}
