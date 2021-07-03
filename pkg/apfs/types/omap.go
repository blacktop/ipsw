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

type omap_phys_t struct {
	Obj              obj_phys_t
	Flags            uint32
	SnapCount        uint32
	TreeType         uint32
	SnapshotTreeType uint32
	TreeOid          oid_t
	SnapshotTreeOid  oid_t
	MostRecentSnap   xid_t
	PendingRevertMin xid_t
	PendingRevertMax xid_t
}

type omap_key_t struct {
	Oid oid_t
	Xid xid_t
}

type omap_val_t struct {
	Flags uint32
	Size  uint32
	Paddr uint64
}

type omap_snapshot_t struct {
	Flags uint32
	Pad   uint32
	Oid   oid_t
}
