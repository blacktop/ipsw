package types

// NOTE: The APFS spec uses camel case for variable names, but in order to
// maintain consistency with the rest of the APFS structures defined in this
// repo, as well as abiding by de facto C conventions, we opt to continue using
// snake case (underscores separating words).

/** `fusion_wbc_phys_t` **/

// typedef struct {
//     ObjPhysT  fwp_obj_hdr;
//     uint64_t    fwp_version;
//     oid_t       fwp_list_head_oid;
//     oid_t       fwp_list_tail_oid;
//     uint64_t    fwp_stable_head_offset;
//     uint64_t    fwp_stable_tail_offset;
//     uint32_t    fwp_list_blocks_count;
//     uint32_t    fwp_reserved;
//     uint64_t    fwp_used_by_rc;
//     prange_t    fwp_rc_stash;
// } fusion_wbc_phys_t;

// /** `fusion_wbc_list_entry_t` **/

// typedef struct {
//     paddr_t     fwle_wbc_lba;
//     paddr_t     fwle_target_lba;
//     uint64_t    fwle_length;
// } fusion_wbc_list_entry_t;

// /** `fusion_wbc_list_phys_t` **/

// typedef struct {
//     ObjPhysT  fwlp_obj_hdr;
//     uint64_t    fwlp_version;
//     uint64_t    fwlp_tail_offset;
//     uint32_t    fwlp_index_begin;
//     uint32_t    fwlp_index_end;
//     uint32_t    fwlp_index_max;
//     uint32_t    fwlp_reserved;
//     fusion_wbc_list_entry_t     fwlp_list_entries[];
// } fusion_wbc_list_phys_t;

// /** Address Markers **/

// #define FUSION_TIER2_DEVICE_BYTE_ADDR   0x4000000000000000ULL

// #define FUSION_TIER2_DEVICE_BLOCK_ADDR(_blksize) \
//     (FUSION_TIER2_DEVICE_BYTE_ADDR >> __builtin_ctzl(_blksize))

// #define FUSION_BLKNO(_fusion_tier2, _blkno, _blksize)   ( \
//     (_fusion_tier2) \
//     ? ( FUSION_TIER2_DEVICE_BLOCK_ADDR(_blksize) | (_blkno) ) \
//     : (_blkno) \
// )

// /** `fusion_mt_key_t` **/

// typedef paddr_t     fusion_mt_key_t;

// /** `fusion_mt_val_t` **/

// typedef struct {
//     paddr_t     fmv_lba;
//     uint32_t    fmv_length;
//     uint32_t    fmv_flags;
// } fusion_mt_val_t;

// /** Fusion Middle-Tree Flags **/

// #define FUSION_MT_DIRTY     (1 << 0)
// #define FUSION_MT_TENANT    (1 << 1)
