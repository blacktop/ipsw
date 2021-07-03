package types

/** `apfs_hash_type_t` --- forward declared for `integrity_meta_phys_t` **/

// typedef enum {
//     APFS_HASH_INVALID       = 0,
//     APFS_HASH_SHA256        = 0x1,
//     APFS_HASH_SHA512_256    = 0x2,
//     APFS_HASH_SHA384        = 0x3,
//     APFS_HASH_SHA512        = 0x4,

//     APFS_HASH_MIN           = APFS_HASH_SHA256,
//     APFS_HASH_MAX           = APFS_HASH_SHA512,

//     APFS_HASH_DEFAULT       = APFS_HASH_SHA256,
// } apfs_hash_type_t;

// #define APFS_HASH_CCSHA256_SIZE         32
// #define APFS_HASH_CCSHA512_256_SIZE     32
// #define APFS_HASH_CCSHA384_SIZE         48
// #define APFS_HASH_CCSHA512_SIZE         64

// #define APFS_HASH_MAX_SIZE              64

// /** `integrity_meta_phys_t` **/

// typedef struct {
//     obj_phys_t          im_o;
//     uint32_t            im_version;

//     // Fields supported by `im_version` >= 1
//     uint32_t            im_flags;
//     apfs_hash_type_t    im_hash_type;
//     uint32_t            im_root_hash_offset;
//     xid_t               im_broken_xid;

//     // Fields supported by `im_version` >= 2
//     uint64_t            im_reserved[9];
// } __attribute__((packed))   integrity_meta_phys_t;

// /** Integrity Metadata Version Constants **/

// enum {
//     INTEGRITY_META_VERSION_INVALID  = 0,
//     INTEGRITY_META_VERSION_1        = 1,
//     INTEGRITY_META_VERSION_2        = 2,
//     INTEGRITY_META_VERSION_HIGHEST  = INTEGRITY_META_VERSION_2,
// };

// /** Integrity Metadata Flags **/

// #define APFS_SEAL_BROKEN    (1U << 0)

// /** `fext_tree_key_t` **/

// typedef struct {
//     uint64_t    private_id;
//     uint64_t    logical_addr;
// } __attribute__((packed))   fext_tree_key_t;

// /** `fext_tree_val_t` **/

// typedef struct {
//     uint64_t    len_and_flags;
//     uint64_t    phys_block_num;
// } __attribute__((packed))   fext_tree_val_t;

// /** `j_file_info_key_t` **/

// typedef struct {
//     j_key_t     hdr;
//     uint64_t    info_and_lba;
// } __attribute__((packed))   j_file_info_key_t;

// #define J_FILE_INFO_LBA_MASK    0x00ffffffffffffffULL
// #define J_FILE_INFO_TYPE_MASK   0xff00000000000000ULL
// #define J_FILE_INFO_TYPE_SHIFT  56

// /** `j_file_data_hash_val_t` --- forward declared for `j_file_info_val_t` **/

// typedef struct {
//     uint16_t    hashed_len;
//     uint8_t     hash_size;
//     uint8_t     hash[0];
// } __attribute__((packed))   j_file_data_hash_val_t;

// /** `j_file_info_val_t` **/

// typedef struct {
//     union {
//         j_file_data_hash_val_t  dhash;
//     };
// } __attribute__((packed))   j_file_info_val_t;

// /** `j_obj_file_info_type` **/

// typedef enum {
//     APFS_FILE_INFO_DATA_HASH    = 1,
// } j_obj_file_info_type;
