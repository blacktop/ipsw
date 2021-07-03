package types

// /** `er_state_phys_t` **/

// // Forward declared for `er_state_phys[_v1]_t`
// typedef struct {
//     ObjPhysT  ersb_o;
//     uint32_t    ersb_magic;
//     uint32_t    ersb_version;
// } er_state_phys_header_t;

// typedef struct {
//     er_state_phys_header_t  ersb_header;
//     uint64_t    ersb_flags;
//     uint64_t    ersb_snap_xid;
//     uint64_t    ersb_current_fext_obj_id;
//     uint64_t    ersb_file_offset;
//     uint64_t    ersb_progress;
//     uint64_t    ersb_total_blk_to_encrypt;
//     oid_t       ersb_blockmap_oid;
//     uint64_t    ersb_tidemark_obj_id;
//     uint64_t    ersb_recovery_extents_count;
//     oid_t       ersb_recovery_list_oid;
//     uint64_t    ersb_recovery_length;
// } er_state_phys_t;

// typedef struct {
//     er_state_phys_header_t  ersb_header;
//     uint64_t    ersb_flags;
//     uint64_t    ersb_snap_xid;
//     uint64_t    ersb_current_fext_obj_id;
//     uint64_t    ersb_file_offset;
//     uint64_t    ersb_fext_pbn;
//     uint64_t    ersb_paddr;
//     uint64_t    ersb_progress;
//     uint64_t    ersb_total_blk_to_encrypt;
//     uint64_t    ersb_blockmap_oid;
//     uint64_t    ersb_checksum_count;
//     uint64_t    ersb_reserved;
//     uint64_t    ersb_fext_cid;
//     uint8_t     ersb_checksum[0];
// } er_state_phys_v1_t;

// /** `er_phase_t` **/

// typedef enum {
//     ER_PHASE_OMAP_ROLL  = 1,
//     ER_PHASE_DATA_ROLL  = 2,
//     ER_PHASE_SNAP_ROLL  = 3,
// } er_phase_t;

// /** `er_recovery_block_phys_t` **/

// typedef struct {
//     ObjPhysT  erb_o;
//     uint64_t    erb_offset;
//     oid_t       erb_next_oid;
//     uint8_t     erb_data[0];
// } er_recovery_block_phys_t;

// /** `gbitmap_block_phys_t` **/

// typedef struct {
//     ObjPhysT  bmb_o;
//     uint64_t    bmb_field[0];
// } gbitmap_block_phys_t;

// /** `gbitmap_phys_t` **/

// typedef struct {
//     ObjPhysT  bm_o;
//     oid_t       bm_tree_oid;
//     uint64_t    bm_bit_count;
//     uint64_t    bm_flags;
// } gbitmap_phys_t;

// /** Encryption-Rolling Checksum Block Sizes **/

// enum {
//     ER_512B_BLOCKSIZE   = 0,
//     ER_2KiB_BLOCKSIZE   = 1,
//     ER_4KiB_BLOCKSIZE   = 2,
//     ER_8KiB_BLOCKSIZE   = 3,
//     ER_16KiB_BLOCKSIZE  = 4,
//     ER_32KiB_BLOCKSIZE  = 5,
//     ER_64KiB_BLOCKSIZE  = 6,
// };

// /** Encryption Rolling Flags **/

// #define ERSB_FLAG_ENCRYPTING            0x00000001
// #define ERSB_FLAG_DECRYPTING            0x00000002
// #define ERSB_FLAG_KEYROLLING            0x00000004
// #define ERSB_FLAG_PAUSED                0x00000008
// #define ERSB_FLAG_FAILED                0x00000010
// #define ERSB_FLAG_CID_IS_TWEAK          0x00000020
// #define ERSB_FLAG_FREE_1                0x00000040
// #define ERSB_FLAG_FREE_2                0x00000080

// #define ERSB_FLAG_CM_BLOCK_SIZE_MASK    0x00000F00
// #define ERSB_FLAG_CM_BLOCK_SIZE_SHIFT   8

// #define ERSB_FLAG_ER_PHASE_MASK         0x00003000
// #define ERSB_FLAG_ER_PHASE_SHIFT        12
// #define ERSB_FLAG_FROM_ONEKEY           0x00004000

// /** Encryption-Rolling Constants **/

// #define ER_CHECKSUM_LENGTH              8
// #define ER_MAGIC                        'FLAB'
// #define ER_VERSION                      1

// #define ER_MAX_CHECKSUM_COUNT_SHIFT     16
// #define ER_CUR_CHECKSUM_COUNT_MASK      0x0000ffff
