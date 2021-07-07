package types

import "math"

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

// OmapPhysT is a omap_phys_t struct
type OmapPhysT struct {
	Obj              ObjPhysT
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

// OMapKey is a omap_key_t struct
type OMapKey struct {
	Oid OidT
	Xid XidT
}

// OMapVal is a omap_val_t struct
type OMapVal struct {
	Flags omapValFlag
	Size  uint32
	Paddr uint64
}

type omap_snapshot_t struct {
	Flags omapSnapshotFlag
	Pad   uint32
	Oid   OidT
}
