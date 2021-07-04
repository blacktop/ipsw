package types

import (
	"time"

	"github.com/blacktop/go-macho/types"
)

const (
	/** Volume Flags **/
	APFS_FS_UNENCRYPTED            = 0x00000001
	APFS_FS_RESERVED_2             = 0x00000002
	APFS_FS_RESERVED_4             = 0x00000004
	APFS_FS_ONEKEY                 = 0x00000008
	APFS_FS_SPILLEDOVER            = 0x00000010
	APFS_FS_RUN_SPILLOVER_CLEANER  = 0x00000020
	APFS_FS_ALWAYS_CHECK_EXTENTREF = 0x00000040
	APFS_FS_RESERVED_80            = 0x00000080
	APFS_FS_RESERVED_100           = 0x00000100

	APFS_FS_FLAGS_VALID_MASK = (APFS_FS_UNENCRYPTED | APFS_FS_RESERVED_2 | APFS_FS_RESERVED_4 | APFS_FS_ONEKEY | APFS_FS_SPILLEDOVER | APFS_FS_RUN_SPILLOVER_CLEANER | APFS_FS_ALWAYS_CHECK_EXTENTREF | APFS_FS_RESERVED_80 | APFS_FS_RESERVED_100)

	APFS_FS_CRYPTOFLAGS = (APFS_FS_UNENCRYPTED | APFS_FS_ONEKEY)

	/** Volume Roles **/
	APFS_VOL_ROLE_NONE = 0x0000

	APFS_VOL_ROLE_SYSTEM    = 0x0001
	APFS_VOL_ROLE_USER      = 0x0002
	APFS_VOL_ROLE_RECOVERY  = 0x0004
	APFS_VOL_ROLE_VM        = 0x0008
	APFS_VOL_ROLE_PREBOOT   = 0x0010
	APFS_VOL_ROLE_INSTALLER = 0x0020

	APFS_VOLUME_ENUM_SHIFT = 6

	APFS_VOL_ROLE_DATA     = (1 << APFS_VOLUME_ENUM_SHIFT) // = 0x0040 --- formerly defined explicitly as `0x0040`
	APFS_VOL_ROLE_BASEBAND = (2 << APFS_VOLUME_ENUM_SHIFT) // = 0x0080 --- formerly defined explicitly as `0x0080`

	// Roles supported since revision 2020-05-15 --- macOS 10.15+, iOS 13+
	APFS_VOL_ROLE_UPDATE      = (3 << APFS_VOLUME_ENUM_SHIFT)  // = 0x00c0
	APFS_VOL_ROLE_XART        = (4 << APFS_VOLUME_ENUM_SHIFT)  // = 0x0100
	APFS_VOL_ROLE_HARDWARE    = (5 << APFS_VOLUME_ENUM_SHIFT)  // = 0x0140
	APFS_VOL_ROLE_BACKUP      = (6 << APFS_VOLUME_ENUM_SHIFT)  // = 0x0180
	APFS_VOL_ROLE_RESERVED_7  = (7 << APFS_VOLUME_ENUM_SHIFT)  // = 0x01c0 --- spec also uses the name `APFS_VOL_ROLE_SIDECAR`, but that could be an error
	APFS_VOL_ROLE_RESERVED_8  = (8 << APFS_VOLUME_ENUM_SHIFT)  // = 0x0200 --- formerly named `APFS_VOL_ROLE_RESERVED_200`
	APFS_VOL_ROLE_ENTERPRISE  = (9 << APFS_VOLUME_ENUM_SHIFT)  // = 0x0240
	APFS_VOL_ROLE_RESERVED_10 = (10 << APFS_VOLUME_ENUM_SHIFT) // = 0x0280
	APFS_VOL_ROLE_PRELOGIN    = (11 << APFS_VOLUME_ENUM_SHIFT) // = 0x02c0

	/** Optional Volume Feature Flags **/
	APFS_FEATURE_DEFRAG_PRERELEASE       = 0x00000001
	APFS_FEATURE_HARDLINK_MAP_RECORDS    = 0x00000002
	APFS_FEATURE_DEFRAG                  = 0x00000004
	APFS_FEATURE_STRICTATIME             = 0x00000008
	APFS_FEATURE_VOLGRP_SYSTEM_INO_SPACE = 0x00000010

	APFS_SUPPORTED_FEATURES_MASK = (APFS_FEATURE_DEFRAG | APFS_FEATURE_DEFRAG_PRERELEASE | APFS_FEATURE_HARDLINK_MAP_RECORDS | APFS_FEATURE_STRICTATIME | APFS_FEATURE_VOLGRP_SYSTEM_INO_SPACE)

	/** Read-Only Comaptible Volume Feature Flags **/
	APFS_SUPPORTED_ROCOMPAT_MASK = 0

	/** Incompatible Volume Feature Flags **/
	APFS_INCOMPAT_CASE_INSENSITIVE          = 0x00000001
	APFS_INCOMPAT_DATALESS_SNAPS            = 0x00000002
	APFS_INCOMPAT_ENC_ROLLED                = 0x00000004
	APFS_INCOMPAT_NORMALIZATION_INSENSITIVE = 0x00000008
	APFS_INCOMPAT_INCOMPLETE_RESTORE        = 0x00000010
	APFS_INCOMPAT_SEALED_VOLUME             = 0x00000020
	APFS_INCOMPAT_RESERVED_40               = 0x00000040

	APFS_SUPPORTED_INCOMPAT_MASK = (APFS_INCOMPAT_CASE_INSENSITIVE | APFS_INCOMPAT_DATALESS_SNAPS | APFS_INCOMPAT_ENC_ROLLED | APFS_INCOMPAT_NORMALIZATION_INSENSITIVE | APFS_INCOMPAT_INCOMPLETE_RESTORE | APFS_INCOMPAT_SEALED_VOLUME | APFS_INCOMPAT_RESERVED_40)
)

const APFS_MODIFIED_NAMELEN = 32

type EpochTime uint64

func (e EpochTime) String() string {
	t := time.Unix(0, int64(e))
	return t.Format(time.UnixDate)
}

type apfs_modified_by_t struct {
	ID        [APFS_MODIFIED_NAMELEN]byte
	Timestamp EpochTime
	LastXid   XidT
}

const (
	APFS_MAGIC       = "APSB"
	APFS_MAX_HIST    = 8
	APFS_VOLNAME_LEN = 256
)

// ApfsSuperblockT is a apfs_superblock_t struct
type ApfsSuperblockT struct {
	Obj ObjPhysT

	Magic   magic
	FsIndex uint32

	Features                   uint64
	ReadonlyCompatibleFeatures uint64
	IncompatibleFeatures       uint64

	UnmountTime EpochTime

	FsReserveBlockCount uint64
	FsQuotaBlockCount   uint64
	FsAllocCount        uint64

	MetaCrypto wrapped_meta_crypto_state_t

	RootTreeType      uint32
	ExtentrefTreeType uint32
	SnapMetaTreeType  uint32

	OmapOid          OidT
	RootTreeOid      OidT
	ExtentrefTreeOid OidT
	SnapMetaTreeOid  OidT

	RevertToXid       XidT
	RevertToSblockOid OidT

	NextObjID uint64

	NumFiles          uint64
	NumDirectories    uint64
	NumSymlinks       uint64
	NumOtherFsobjects uint64
	NumSnapshots      uint64

	TotalBlockAlloced uint64
	TotalBlocksFreed  uint64

	VolumeUUID  types.UUID
	LastModTime EpochTime

	FsFlags uint64

	FormattedBy apfs_modified_by_t
	ModifiedBy  [APFS_MAX_HIST]apfs_modified_by_t

	VolumeName [APFS_VOLNAME_LEN]byte
	NextDocID  uint32

	Role     uint16
	Reserved uint16

	RootToXid  XidT
	ErStateOid OidT

	/* Fields introduced in revision 2020-05-15 */

	// Fields supported on macOS 10.13.3+
	CloneinfoIDEpoch EpochTime
	CloneinfoXid     uint64

	// Fields supported on macOS 10.15+
	SnapMetaExtOid OidT
	VolumeGroupID  types.UUID

	/* Fields introduced in revision 2020-06-22 */

	// Fields supported on macOS 11+
	IntegrityMetaOid OidT
	FextTreeOid      OidT
	FextTreeType     uint32

	ReservedType uint32
	ReservedOid  OidT
}
