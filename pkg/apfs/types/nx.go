package types

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/blacktop/go-macho/types"
)

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

type nxFeature uint64
type nxIncompatFeature uint64
type nxContainerFlag uint64

const (
	/** Container Flags **/
	NX_RESERVED_1 nxContainerFlag = 0x00000001
	NX_RESERVED_2 nxContainerFlag = 0x00000002
	NX_CRYPTO_SW  nxContainerFlag = 0x00000004

	/** Optional Container Feature Flags **/
	NX_FEATURE_DEFRAG          nxFeature = 0x0000000000000001
	NX_FEATURE_LCFD            nxFeature = 0x0000000000000002
	NX_SUPPORTED_FEATURES_MASK           = (NX_FEATURE_DEFRAG | NX_FEATURE_LCFD)

	/** Read-Only Compatible Container Feature Flags **/
	NX_SUPPORTED_ROCOMPAT_MASK = 0

	/** Incompatible Container Feature Flags **/
	NX_INCOMPAT_VERSION1       nxIncompatFeature = 0x0000000000000001
	NX_INCOMPAT_VERSION2       nxIncompatFeature = 0x0000000000000002
	NX_INCOMPAT_FUSION         nxIncompatFeature = 0x0000000000000100
	NX_SUPPORTED_INCOMPAT_MASK                   = (NX_INCOMPAT_VERSION2 | NX_INCOMPAT_FUSION)

	/** Block and Container Size **/
	NX_MINIMUM_BLOCK_SIZE     = 0x1000   // =    4 Ki
	NX_DEFAULT_BLOCK_SIZE     = 0x1000   // =    4 Ki
	NX_MAXIMUM_BLOCK_SIZE     = 0x10000  // =   64 Ki
	NX_MINIMUM_CONTAINER_SIZE = 0x100000 // = 1024 Ki = 1 Mi
)

// NxSuperblockT nx_superblock_t struct
type NxSuperblockT struct {
	Obj        ObjPhysT
	Magic      magic
	BlockSize  uint32
	BlockCount uint64

	Features                   nxFeature
	ReadOnlyCompatibleFeatures uint64
	IncompatibleFeatures       nxIncompatFeature

	UUID types.UUID

	NextOid OidT
	NextXid XidT

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

	SpacemanOid OidT
	OmapOid     OidT
	ReaperOid   OidT

	TestType uint32

	MaxFileSystems      uint32
	FsOids              [NX_MAX_FILE_SYSTEMS]OidT
	Counters            [NX_NUM_COUNTERS]uint64
	BlockedOutPRange    prange
	EvictMappingTreeOid OidT
	Flags               nxContainerFlag
	EFIJumpstart        uint64
	FusionUUID          types.UUID
	Keylocker           prange
	EphemeralInfos      [NX_EPH_INFO_COUNT]uint64

	TestOid OidT

	FusionMtOid  OidT
	FusionWbcOid OidT
	FusionWbc    prange

	NewestMountedVersion uint64

	MkBLocker prange
}

type NxSuperblock struct {
	NxSuperblockT

	OMap *OMap

	block
}

// ReadNxSuperblock returns a verified NxSuperblock or error if block does not verify
func ReadNxSuperblock(r *io.SectionReader) (*NxSuperblock, error) {
	sr := io.NewSectionReader(r, 0, 1<<63-1)

	sb := &NxSuperblock{
		block: block{
			Addr: 0,
			Size: NX_DEFAULT_BLOCK_SIZE,
			Data: make([]byte, NX_DEFAULT_BLOCK_SIZE),
		},
	}

	if err := binary.Read(sr, binary.LittleEndian, &sb.Data); err != nil {
		return nil, fmt.Errorf("failed to read %#x sized block data: %v", NX_DEFAULT_BLOCK_SIZE, err)
	}

	sb.r = bytes.NewReader(sb.Data)

	if err := binary.Read(sb.r, binary.LittleEndian, &sb.NxSuperblockT); err != nil {
		return nil, fmt.Errorf("failed to read APFS nx_superblock_t: %v", err)
	}

	if sb.Magic.String() != NX_MAGIC {
		return nil, fmt.Errorf("found unexpected nx_superblock_t magic: %s, expected: %s", sb.Magic.String(), NX_MAGIC)
	}

	if !VerifyChecksum(sb.Data) {
		return nil, fmt.Errorf("nx_superblock_t data block failed checksum validation")
	}

	return sb, nil
}

type CheckpointDesc struct {
	Obj  ObjPhysT
	Body interface{}
}

type CheckpointMappingT struct {
	Type    objType
	SubType objType
	Size    uint32
	Pad     uint32
	FsOid   OidT
	Oid     OidT
	Paddr   OidT
}

type CheckpointMapPhysT struct {
	Obj   ObjPhysT
	Flags cpMapFlag
	Count uint32
	// Map   []CheckpointMappingT
}

type CheckpointMapPhys struct {
	Hdr CheckpointMapPhysT
	Map []CheckpointMappingT
}
type cpMapFlag uint32

/** Checkpoint Flags **/
const CHECKPOINT_MAP_LAST cpMapFlag = 0x00000001

type EvictMappingValT struct {
	DstPaddr uint64
	Len      uint64
} // __attribute__((packed))
