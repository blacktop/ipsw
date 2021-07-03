package types

type chunk_info_t struct {
	Xid        xid_t // Spec says ``, but I assume it is meant to be `xid_t` they're equivalent, anyway
	Addr       uint64
	BlockCount uint32
	FreeCount  uint32
	BitmapAddr uint64
}

type chunk_info_block_t struct {
	Obj            ObjPhysT
	Index          uint32
	ChunkInfoCount uint32
	ChunkInfo      []chunk_info_t
}

type cib_addr_block_t struct {
	Obj      ObjPhysT
	Index    uint32
	CibCount uint32
	CibAddr  []uint64
}

type spaceman_free_queue_key_t struct {
	SfqkXid   xid_t
	SfqkPaddr uint64
}

type spaceman_free_queue_val_t uint64

type spaceman_free_queue_entry_t struct {
	SfqeKey   spaceman_free_queue_key_t
	SfqeCount spaceman_free_queue_val_t
}

type spaceman_free_queue_t struct {
	Count         uint64
	TreeOid       oid_t
	OldestXid     xid_t
	TreeNodeLimit uint16
	Pad16         uint16
	Pad32         uint32
	Reserved      uint64
}

type spaceman_device_t struct {
	BlockCount uint64
	ChunkCount uint64
	CibCount   uint32
	CabCount   uint32
	FreeCount  uint64
	AddrOffset uint32
	Reserved   uint32
	Reserved2  uint64
}

type spaceman_allocation_zone_boundaries_t struct {
	ZoneStart uint64
	ZoneEnd   uint64
}

const (
	SM_ALLOCZONE_INVALID_END_BOUNDARY    = 0
	SM_ALLOCZONE_NUM_PREVIOUS_BOUNDARIES = 7
)

type spaceman_allocation_zone_info_phys_t struct {
	CurrentBoundaries     spaceman_allocation_zone_boundaries_t
	PreviousBoundaries    [SM_ALLOCZONE_NUM_PREVIOUS_BOUNDARIES]spaceman_allocation_zone_boundaries_t
	ZoneID                uint16
	PreviousBoundaryIndex uint16
	Reserved              uint32
}

type smdev byte // FIXME: type
const (
	SD_MAIN  smdev = 0
	SD_TIER2 smdev = 1
	SD_COUNT smdev = 2
)

const SM_DATAZONE_ALLOCZONE_COUNT = 8

type spaceman_datazone_info_phys_t struct {
	AllocationZones [SD_COUNT][SM_DATAZONE_ALLOCZONE_COUNT]spaceman_allocation_zone_info_phys_t
}

type sfq byte // FIXME: type
const (
	SFQ_IP    sfq = 0
	SFQ_MAIN  sfq = 1
	SFQ_TIER2 sfq = 2
	SFQ_COUNT sfq = 3
)

type spaceman_phys_t struct {
	Obj            ObjPhysT
	BlockSize      uint32
	BlocksPerChunk uint32
	ChunksPerCib   uint32
	CibsPerCab     uint32

	Dev [SD_COUNT]spaceman_device_t

	Flags               uint32
	IPBmTxMultiplier    uint32
	IPBlockCount        uint64
	IPBmSizeInBlocks    uint32
	IPBmBlockCount      uint32
	IPBmBase            uint64
	IPBase              uint64
	FsReserveBlockCount uint64
	FsReserveAllocCount uint64

	Fq [SFQ_COUNT]spaceman_free_queue_t

	IPBmFreeHead       uint16
	IPBmFreeTail       uint16
	IPBmXidOffset      uint32
	IPBitmapOffset     uint32
	IPBmFreeNextOffset uint32
	Version            uint32
	StructSize         uint32

	Datazone spaceman_datazone_info_phys_t
}

const (
	SM_FLAG_VERSIONED = 0x00000001

	/** Chunk Info Block Constants **/
	CI_COUNT_MASK          = 0x000fffff
	CI_COUNT_RESERVED_MASK = 0xfff00000

	/** Internal-Pool Bitmap **/
	SPACEMAN_IP_BM_TX_MULTIPLIER   = 16
	SPACEMAN_IP_BM_INDEX_INVALID   = 0xfff
	SPACEMAN_IP_BM_BLOCK_COUNT_MAX = 0xffe
)
