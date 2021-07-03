package types

/** `nx_repear_phys_t` **/

// typedef struct {
//     obj_phys_t  nr_o;
//     uint64_t    nr_next_reap_id;
//     uint64_t    nr_completed_id;
//     oid_t       nr_head;
//     oid_t       nr_tail;
//     uint32_t    nr_flags;
//     uint32_t    nr_rlcount;
//     uint32_t    nr_type;
//     uint32_t    nr_size;
//     oid_t       nr_fs_oid;
//     oid_t       nr_oid;
//     xid_t       nr_xid;
//     uint32_t    nr_nrle_flags;
//     uint32_t    nr_state_buffer_size;
//     uint8_t     nr_state_buffer[];
// } nx_repear_phys_t;

// /** `nx_reap_list_entry_t` --- forward declared for `nx_reap_list_phys_t` **/

// typedef struct {
//     uint32_t    nrle_next;
//     uint32_t    nrle_flags;
//     uint32_t    nrle_type;
//     uint32_t    nrle_size;
//     oid_t       nrle_fs_oid;
//     oid_t       nrle_oid;
//     xid_t       nrle_xid;
// } nx_reap_list_entry_t;

// /** `nx_reap_list_phys_t` **/

// typedef struct {
//     obj_phys_t              nrl_o;
//     oid_t                   nrl_next;
//     uint32_t                nrl_flags;
//     uint32_t                nrl_max;
//     uint32_t                nrl_count;
//     uint32_t                nrl_first;
//     uint32_t                nrl_last;
//     uint32_t                nrl_free;
//     nx_reap_list_entry_t    nrl_entries[];
// } nx_reap_list_phys_t;

// /** Volume Reaper States **/

// enum {
//     APFS_REAP_PHASE_START           = 0,
//     APFS_REAP_PHASE_SNAPSHOTS       = 1,
//     APFS_REAP_PHASE_ACTIVE_FS       = 2,
//     APFS_REAP_PHASE_DESTROY_OMAP    = 3,
//     APFS_REAP_PHASE_DONE            = 4,
// };

// /** Reaper Flags **/

// #define NR_BHM_FLAG     0x00000001
// #define NR_CONTINUE     0x00000002

// /** Reaper List Entry Flags **/

// #define NRLE_VALID              0x00000001
// #define NRLE_REAP_ID_RECORD     0x00000002
// #define NRLE_CALL               0x00000004
// #define NRLE_COMPETITION        0x00000008
// #define NRLE_CLEANUP            0x00000010

// /** Reaper List Flags **/

// #define NRL_INDEX_INVALID       0xffffffff

// /** `omap_reap_state_t` **/

// typedef struct {
//     uint32_t    omr_phase;
//     omap_key_t  omr_ok;
// } omap_reap_state_t;

// /** `omap_cleanup_state_t` **/

// typedef struct {
//     uint32_t    omc_cleaning;
//     uint32_t    omc_omsflags;
//     xid_t       omc_sxidprev;
//     xid_t       omc_sxidstart;
//     xid_t       omc_sxidenf;
//     xid_t       omc_sxidnext;
//     omap_key_t  omc_curkey;
// } omap_cleanup_state_t;

// /** `apfs_reap_state_t` **/

// typedef struct {
//     uint64_t    last_pbn;
//     xid_t       cur_snap_xid;
//     uint32_t    phase;
// } __attribute__((packed))   apfs_reap_state_t;
