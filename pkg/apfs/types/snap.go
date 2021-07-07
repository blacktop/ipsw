package types

/** `j_snap_metadata_key_t` **/

// typedef struct {
//     JKeyT     hdr;
// } __attribute__((packed))   j_snap_metadata_key_t;

// /** `j_snap_metadata_val_t` **/

// typedef struct {
//     OidT       extentref_tree_oid;
//     OidT       sblock_oid;
//     uint64_t    create_time;
//     uint64_t    change_time;
//     uint64_t    inum;
//     uint32_t    extentref_tree_type;
//     uint32_t    flags;
//     uint16_t    name_len;
//     uint8_t     name[0];
// } __attribute__((packed))   j_snap_metadata_val_t;

// /** `j_snap_name_key_t` **/

// typedef struct {
//     JKeyT     hdr;
//     uint16_t    name_len;
//     uint8_t     name[0];
// } __attribute__((packed))   j_snap_name_key_t;

// /** `j_snap_name_val_t` **/

// typedef struct {
//     XidT   snap_xid;
// } __attribute__((packed))   j_snap_name_val_t;

// /** `snap_meta_flags` **/

// typedef enum {
//     SNAP_META_PENDING_DATALESS  = 0x00000001,
// } snap_meta_flags;

// /** `snap_meta_ext_t` --- forward declared for `snap_meta_ext_obj_phys_t` **/

// typedef struct {
//     uint32_t    sme_version;

//     uint32_t    sme_flags;
//     XidT       sme_snap_xid;
//     uuid_t      sme_uuid;

//     uint64_t    sme_token;
// } __attribute__((packed))   snap_meta_ext_t;

// /** `snap_meta_ext_obj_phys_t` **/

// typedef struct {
//     ObjPhysT          smeop_o;
//     snap_meta_ext_t     smeop_sme;
// } __attribute__((packed)) snap_meta_ext_obj_phys_t;
