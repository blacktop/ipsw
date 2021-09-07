package types

import (
	"fmt"
	"math"
	"strings"
)

//go:generate stringer -type=omapValFlag,omapSnapshotFlag,omapFlag -output omap_string.go

type omapValFlag uint32
type omapSnapshotFlag uint32
type omapFlag uint32

const (
	/** Object Map Value Flags **/
	OMAP_VAL_DELETED           omapValFlag = 0x00000001
	OMAP_VAL_SAVED             omapValFlag = 0x00000002
	OMAP_VAL_ENCRYPTED         omapValFlag = 0x00000004
	OMAP_VAL_NOHEADER          omapValFlag = 0x00000008
	OMAP_VAL_CRYPTO_GENERATION omapValFlag = 0x00000010

	/** Snapshot Flags **/
	OMAP_SNAPSHOT_DELETED  omapSnapshotFlag = 0x00000001
	OMAP_SNAPSHOT_REVERTED omapSnapshotFlag = 0x00000002

	/** Object Map Flags **/
	OMAP_MANUALLY_MANAGED  omapFlag = 0x00000001
	OMAP_ENCRYPTING        omapFlag = 0x00000002
	OMAP_DECRYPTING        omapFlag = 0x00000004
	OMAP_KEYROLLING        omapFlag = 0x00000008
	OMAP_CRYPTO_GENERATION omapFlag = 0x00000010

	OMAP_VALID_FLAGS = 0x0000001f

	/** Object Map Constants **/
	OMAP_MAX_SNAP_COUNT = math.MaxUint32

	/** Object Map Reaper Phases **/
	OMAP_REAP_PHASE_MAP_TREE      = 1
	OMAP_REAP_PHASE_SNAPSHOT_TREE = 2
)

// OMapPhysT is a omap_phys_t struct
type OMapPhysT struct {
	// Obj              ObjPhysT
	Flags            omapFlag
	SnapCount        uint32
	TreeType         objType
	SnapshotTreeType objType
	TreeOid          OidT
	SnapshotTreeOid  OidT
	MostRecentSnap   XidT
	PendingRevertMin XidT
	PendingRevertMax XidT
}

type OMap struct {
	OMapPhysT

	Tree         *Obj
	SnapshotTree *Obj

	block
}

// OMapKey is a omap_key_t struct
type OMapKey struct {
	Oid OidT
	Xid XidT
}

func (k OMapKey) String() string {
	return fmt.Sprintf("oid=%#x, xid=%#x", k.Oid, k.Xid)
}

// OMapVal is a omap_val_t struct
type OMapVal struct {
	Flags omapValFlag
	Size  uint32
	Paddr uint64
}

func (v OMapVal) String() string {
	return fmt.Sprintf("flags=%s, size=%#x, paddr=%#x", v.Flags, v.Size, v.Paddr)
}

// OMapSnapshotT is a omap_snapshot_t
type OMapSnapshotT struct {
	Flags omapSnapshotFlag
	Pad   uint32
	Oid   OidT
}

func (s OMapSnapshotT) String() string {
	return fmt.Sprintf("oid=%#x, flags=%s", s.Oid, s.Flags)
}

type FextNodeEntry struct {
	Offset interface{}
	Key    fext_tree_key_t
	Val    fext_tree_val_t
}

func (f FextNodeEntry) String() string {
	var fout []string
	switch off := f.Offset.(type) {
	case KVOffT:
		fout = append(fout, fmt.Sprintf("(key_offset=%d, val_offset=%d)", off.Key, off.Val))
	case KVLocT:
		fout = append(fout, fmt.Sprintf("(key_off=%d, key_len=%d, val_off=%d, val_len=%d)", off.Key.Off, off.Key.Len, off.Val.Off, off.Val.Len))
	}
	fout = append(fout, f.Key.String(), f.Val.String())
	return strings.Join(fout, ", ")
}

type SpacemanFreeQueueNodeEntry struct {
	Offset interface{}
	Key    spaceman_free_queue_key_t
	Val    spaceman_free_queue_val_t
}

func (s SpacemanFreeQueueNodeEntry) String() string {
	var sout []string
	switch off := s.Offset.(type) {
	case KVOffT:
		sout = append(sout, fmt.Sprintf("(key_offset=%d, val_offset=%d)", off.Key, off.Val))
	case KVLocT:
		sout = append(sout, fmt.Sprintf("(key_off=%d, key_len=%d, val_off=%d, val_len=%d)", off.Key.Off, off.Key.Len, off.Val.Off, off.Val.Len))
	}
	sout = append(sout, s.Key.String(), s.Val.String())
	return strings.Join(sout, ", ")
}

type OMapNodeEntry struct {
	Offset interface{}
	Key    OMapKey
	PAddr  uint64
	OMap   *Obj
	Val    OMapVal
}

func (one OMapNodeEntry) String() string {
	var nout []string

	switch off := one.Offset.(type) {
	case KVOffT:
		nout = append(nout, fmt.Sprintf("(key_offset=%d, val_offset=%d)", off.Key, off.Val))
	case KVLocT:
		nout = append(nout, fmt.Sprintf("(key_off=%d, key_len=%d, val_off=%d, val_len=%d)", off.Key.Off, off.Key.Len, off.Val.Off, off.Val.Len))
	}

	nout = append(nout, fmt.Sprintf("key={%s}", one.Key))

	if one.PAddr > 0 {
		nout = append(nout, fmt.Sprintf("paddr=%#x", one.PAddr))
	}

	if one.OMap != nil {
		nout = append(nout, fmt.Sprintf("omap=%s", one.OMap))
	}

	nout = append(nout, fmt.Sprintf("value={%s}", one.Val))

	return strings.Join(nout, ", ")
}

type NodeEntry struct {
	Offset interface{}
	Hdr    JKeyT
	Key    interface{}
	PAddr  uint64
	Val    interface{}
}

func (ne NodeEntry) String() string {
	var nout []string

	nout = append(nout, fmt.Sprintf("%s oid=%d", typeColor(ne.Hdr.GetType()), ne.Hdr.GetID()))

	// switch off := ne.Offset.(type) {
	// case KVOffT:
	// 	nout = append(nout, fmt.Sprintf("(key_offset=%d, val_offset=%d)", off.Key, off.Val))
	// case KVLocT:
	// 	nout = append(nout, fmt.Sprintf("(key_off=%d, key_len=%d, val_off=%d, val_len=%d)", off.Key.Off, off.Key.Len, off.Val.Off, off.Val.Len))
	// }

	switch ne.Hdr.GetType() {
	case APFS_TYPE_SNAP_METADATA:
	case APFS_TYPE_EXTENT:
	case APFS_TYPE_INODE:
	case APFS_TYPE_XATTR:
		nout = append(nout, fmt.Sprintf("name=%s", nameColor(ne.Key.(j_xattr_key_t).Name)))
	case APFS_TYPE_SIBLING_LINK:
		nout = append(nout, fmt.Sprintf("sibling_id=%#x", ne.Key.(SiblingKeyT).SiblingID))
	case APFS_TYPE_DSTREAM_ID:
	case APFS_TYPE_CRYPTO_STATE:
	case APFS_TYPE_FILE_EXTENT:
		nout = append(nout, fmt.Sprintf("logical_addr=%#x", ne.Key.(j_file_extent_key_t).LogicalAddr))
	case APFS_TYPE_DIR_REC:
		nout = append(nout, fmt.Sprintf("name=%s, hash=%#x", nameColor(ne.Key.(JDrecHashedKeyT).Name), ne.Key.(JDrecHashedKeyT).Hash()))
	case APFS_TYPE_DIR_STATS:
	case APFS_TYPE_SNAP_NAME:
		nout = append(nout, fmt.Sprintf("name=%s", nameColor(ne.Key.(j_snap_name_key_t).Name)))
	case APFS_TYPE_SIBLING_MAP:
	case APFS_TYPE_FILE_INFO:
		nout = append(nout, fmt.Sprintf("lba=%#x, info=%s", ne.Key.(j_file_info_key_t).LBA(), ne.Key.(j_file_info_key_t).Info()))
	}

	if ne.PAddr > 0 {
		nout = append(nout, fmt.Sprintf("paddr=%#x", ne.PAddr))
	}

	switch ne.Hdr.GetType() {
	case APFS_TYPE_SNAP_METADATA:
		nout = append(nout, ne.Val.(j_snap_metadata_val).String())
	case APFS_TYPE_EXTENT:
		nout = append(nout, ne.Val.(j_phys_ext_val_t).String())
	case APFS_TYPE_INODE:
		switch val := ne.Val.(type) {
		case BTreeNodeIndexNodeValT:
			nout = append(nout, val.String())
		case uint64:
			nout = append(nout, fmt.Sprintf("val=%#x", val))
		case JInodeVal:
			nout = append(nout, val.String())
		}
	case APFS_TYPE_XATTR:
		switch val := ne.Val.(type) {
		case BTreeNodeIndexNodeValT:
			nout = append(nout, val.String())
		case uint64:
			nout = append(nout, fmt.Sprintf("val=%#x", val))
		case j_xattr_val_t:
			nout = append(nout, val.String())
		}
	case APFS_TYPE_SIBLING_LINK:
		switch val := ne.Val.(type) {
		case BTreeNodeIndexNodeValT:
			nout = append(nout, val.String())
		case uint64:
			nout = append(nout, fmt.Sprintf("val=%#x", val))
		case SiblingValT:
			nout = append(nout, val.String())
		}
	case APFS_TYPE_DSTREAM_ID:
		switch val := ne.Val.(type) {
		case BTreeNodeIndexNodeValT:
			nout = append(nout, val.String())
		case uint64:
			nout = append(nout, fmt.Sprintf("val=%#x", val))
		case j_dstream_id_val_t:
			nout = append(nout, val.String())
		}
	case APFS_TYPE_CRYPTO_STATE:
		switch val := ne.Val.(type) {
		case BTreeNodeIndexNodeValT:
			nout = append(nout, val.String())
		case uint64:
			nout = append(nout, fmt.Sprintf("val=%#x", val))
		case j_crypto_val_t:
			nout = append(nout, val.String())
		}
	case APFS_TYPE_FILE_EXTENT:
		switch val := ne.Val.(type) {
		case BTreeNodeIndexNodeValT:
			nout = append(nout, val.String())
		case uint64:
			nout = append(nout, fmt.Sprintf("val=%#x", val))
		case j_file_extent_val_t:
			nout = append(nout, val.String())
		}
	case APFS_TYPE_DIR_REC:
		switch val := ne.Val.(type) {
		case BTreeNodeIndexNodeValT:
			nout = append(nout, val.String())
		case uint64:
			nout = append(nout, fmt.Sprintf("val=%#x", val))
		case JDrecVal:
			nout = append(nout, val.String())
		}
	case APFS_TYPE_DIR_STATS:
		switch val := ne.Val.(type) {
		case BTreeNodeIndexNodeValT:
			nout = append(nout, val.String())
		case uint64:
			nout = append(nout, fmt.Sprintf("val=%#x", val))
		case j_dir_stats_val_t:
			nout = append(nout, val.String())
		}
	case APFS_TYPE_SNAP_NAME:
		nout = append(nout, ne.Val.(j_snap_name_val_t).String())
	case APFS_TYPE_SIBLING_MAP:
		switch val := ne.Val.(type) {
		case BTreeNodeIndexNodeValT:
			nout = append(nout, val.String())
		case uint64:
			nout = append(nout, fmt.Sprintf("val=%#x", val))
		case SiblingMapValT:
			nout = append(nout, val.String())
		}
	case APFS_TYPE_FILE_INFO:
		switch val := ne.Val.(type) {
		case BTreeNodeIndexNodeValT:
			nout = append(nout, val.String())
		case uint64:
			nout = append(nout, fmt.Sprintf("val=%#x", val))
		case j_file_info_val_t:
			nout = append(nout, val.String())
		}
	}

	return strings.Join(nout, ", ")
}
