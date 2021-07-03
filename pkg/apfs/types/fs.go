package types

import "github.com/blacktop/go-macho/types"

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

type apfs_modified_by_t struct {
	id        [APFS_MODIFIED_NAMELEN]byte
	timestamp uint64
	last_xid  xid_t
}

const (
	APFS_MAGIC       = `BSPA`
	APFS_MAX_HIST    = 8
	APFS_VOLNAME_LEN = 256
)

type apfs_superblock_t struct {
	apfs_o obj_phys_t

	apfs_magic    uint32
	apfs_fs_index uint32

	apfs_features                     uint64
	apfs_readonly_compatible_features uint64
	apfs_incompatible_features        uint64

	apfs_unmount_time uint64

	apfs_fs_reserve_block_count uint64
	apfs_fs_quota_block_count   uint64
	apfs_fs_alloc_count         uint64

	apfs_meta_crypto wrapped_meta_crypto_state_t

	apfs_root_tree_type      uint32
	apfs_extentref_tree_type uint32
	apfs_snap_meta_tree_type uint32

	apfs_omap_oid           oid_t
	apfs_root_tree_oid      oid_t
	apfs_extentref_tree_oid oid_t
	apfs_snap_meta_tree_oid oid_t

	apfs_revert_to_xid        xid_t
	apfs_revert_to_sblock_oid oid_t

	apfs_next_obj_id uint64

	apfs_num_files           uint64
	apfs_num_directories     uint64
	apfs_num_symlinks        uint64
	apfs_num_other_fsobjects uint64
	apfs_num_snapshots       uint64

	apfs_total_block_alloced uint64
	apfs_total_blocks_freed  uint64

	apfs_vol_uuid      types.UUID
	apfs_last_mod_time uint64

	apfs_fs_flags uint64

	apfs_formatted_by apfs_modified_by_t
	apfs_modified_by  [APFS_MAX_HIST]apfs_modified_by_t

	apfs_volname     [APFS_VOLNAME_LEN]byte
	apfs_next_doc_id uint32

	apfs_role uint16
	reserved  uint16

	apfs_root_to_xid  xid_t
	apfs_er_state_oid oid_t

	// Fields introduced in revision 2020-05-15

	// Fields supported on macOS 10.13.3+
	apfs_cloneinfo_id_epoch uint64
	apfs_cloneinfo_xid      uint64

	// Fields supported on macOS 10.15+
	apfs_snap_meta_ext_oid oid_t
	apfs_volume_group_id   types.UUID

	// Fields introduced in revision 2020-06-22

	// Fields supported on macOS 11+
	apfs_integrity_meta_oid oid_t
	apfs_fext_tree_oid      oid_t
	apfs_fext_tree_type     uint32

	reserved_type uint32
	reserved_oid  oid_t
}
