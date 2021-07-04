package types

import "math"

const (
	/** Object Map Value Flags **/
	OMAP_VAL_DELETED           = 0x00000001
	OMAP_VAL_SAVED             = 0x00000002
	OMAP_VAL_ENCRYPTED         = 0x00000004
	OMAP_VAL_NOHEADER          = 0x00000008
	OMAP_VAL_CRYPTO_GENERATION = 0x00000010

	/** Snapshot Flags **/
	OMAP_SNAPSHOT_DELETED  = 0x00000001
	OMAP_SNAPSHOT_REVERTED = 0x00000002

	/** Object Map Flags **/
	OMAP_MANUALLY_MANAGED  = 0x00000001
	OMAP_ENCRYPTING        = 0x00000002
	OMAP_DECRYPTING        = 0x00000004
	OMAP_KEYROLLING        = 0x00000008
	OMAP_CRYPTO_GENERATION = 0x00000010

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
	Flags            uint32
	SnapCount        uint32
	TreeType         uint32
	SnapshotTreeType uint32
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
	Flags uint32
	Size  uint32
	Paddr uint64
}

type omap_snapshot_t struct {
	Flags uint32
	Pad   uint32
	Oid   OidT
}
