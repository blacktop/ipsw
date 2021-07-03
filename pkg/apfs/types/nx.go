package types

import "github.com/blacktop/go-macho/types"

type nx_counter_id_t byte //FIXME: what type
const (
	NX_CNTR_OBJ_CKSUM_SET  nx_counter_id_t = 0
	NX_CNTR_OBJ_CKSUM_FAIL nx_counter_id_t = 1

	NX_NUM_COUNTERS nx_counter_id_t = 32
)

const (
	NX_MAGIC            = "NXSB"
	NX_MAX_FILE_SYSTEMS = 100

	NX_EPH_INFO_COUNT              = 4
	NX_EPH_MIN_BLOCK_COUNT         = 8
	NX_MAX_FILE_SYSTEM_EPH_STRUCTS = 4
	NX_TX_MIN_CHECKPOINT_COUNT     = 4
	NX_EPH_INFO_VERSION            = 1
)

// NxSuperblockT nx_superblock_t struct
type NxSuperblockT struct {
	Obj        ObjPhysT
	Magic      magic
	BlockSize  uint32
	BlockCount uint64

	Features                   uint64
	ReadonlyCompatibleFeatures uint64
	IncompatibleFeatures       uint64

	UUID types.UUID

	NextOid oid_t
	NextXid xid_t

	XpDescBlocks uint32
	XpDataBlocks uint32
	XpDescBase   uint64
	XpDataBase   uint64
	XpDescNext   uint32
	XpDataNext   uint32
	XpDescIndex  uint32
	XpDescLen    uint32
	XpDataIndex  uint32
	XpDataLen    uint32

	SpacemanOid oid_t
	OmapOid     oid_t
	ReaperOid   oid_t

	TestType uint32

	MaxFileSystems      uint32
	FsOid               [NX_MAX_FILE_SYSTEMS]oid_t
	Counters            [NX_NUM_COUNTERS]uint64
	BlockedOutPrange    prange
	EvictMappingTreeOid oid_t
	Flags               uint64
	EFIJumpstart        uint64
	FusionUUID          types.UUID
	Keylocker           prange
	EphemeralInfo       [NX_EPH_INFO_COUNT]uint64

	TestOid oid_t

	FusionMtOid  oid_t
	FusionWbcOid oid_t
	FusionWbc    prange

	NewestMountedVersion uint64

	MkbLocker prange
}

const (
	/** Container Flags **/
	NX_RESERVED_1 = 0x00000001
	NX_RESERVED_2 = 0x00000002
	NX_CRYPTO_SW  = 0x00000004

	/** Optional Container Feature Flags **/
	NX_FEATURE_DEFRAG          = 0x0000000000000001
	NX_FEATURE_LCFD            = 0x0000000000000002
	NX_SUPPORTED_FEATURES_MASK = (NX_FEATURE_DEFRAG | NX_FEATURE_LCFD)

	/** Read-Only Compatible Container Feature Flags **/
	NX_SUPPORTED_ROCOMPAT_MASK = 0

	/** Incompatible Container Feature Flags **/
	NX_INCOMPAT_VERSION1       = 0x0000000000000001
	NX_INCOMPAT_VERSION2       = 0x0000000000000002
	NX_INCOMPAT_FUSION         = 0x0000000000000100
	NX_SUPPORTED_INCOMPAT_MASK = (NX_INCOMPAT_VERSION2 | NX_INCOMPAT_FUSION)

	/** Block and Container Size **/
	NX_MINIMUM_BLOCK_SIZE     = 0x1000   // =    4 Ki
	NX_DEFAULT_BLOCK_SIZE     = 0x1000   // =    4 Ki
	NX_MAXIMUM_BLOCK_SIZE     = 0x10000  // =   64 Ki
	NX_MINIMUM_CONTAINER_SIZE = 0x100000 // = 1024 Ki = 1 Mi
)

type CheckpointDesc struct {
	Obj  ObjPhysT
	Body interface{}
}

type CheckpointMappingT struct {
	Type    objType
	Subtype uint32
	Size    uint32
	Pad     uint32
	FsOid   oid_t
	Oid     oid_t
	Paddr   oid_t
}

type CheckpointMapPhysT struct {
	Obj   ObjPhysT
	Flags uint32
	Count uint32
	// Map   []CheckpointMappingT
}

type CheckpointMapPhys struct {
	Hdr CheckpointMapPhysT
	Map []CheckpointMappingT
}

/** Checkpoint Flags **/
const CHECKPOINT_MAP_LAST = 0x00000001

type EvictMappingValT struct {
	DstPaddr uint64
	Len      uint64
} // __attribute__((packed))
