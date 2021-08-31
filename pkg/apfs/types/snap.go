package types

import "github.com/blacktop/go-macho"

type j_snap_metadata_key_t struct {
	Hdr JKeyT
} // __attribute__((packed))

type j_snap_metadata_val_t struct {
	ExtentrefTreeOid  OidT
	SblockOid         OidT
	CreateTime        uint64
	ChangeTime        uint64
	INum              uint64
	ExtentRefTreeType objType
	Flags             uint32
	NameLen           uint16
	Name              [0]uint8
} // __attribute__((packed))

type j_snap_name_key_t struct {
	// Hdr     JKeyT
	NameLen uint16
	Name    string
} // __attribute__((packed))

/** `j_snap_name_val_t` **/

type j_snap_name_val_t struct {
	SnapXid XidT
} // __attribute__((packed))

type snap_meta_flags uint32

const (
	SNAP_META_PENDING_DATALESS snap_meta_flags = 0x00000001
)

/** `snap_meta_ext_t` --- forward declared for `snap_meta_ext_obj_phys_t` **/
type snap_meta_ext_t struct {
	Version uint32

	Flags   uint32
	SnapXid XidT
	UUID    macho.UUID

	Token uint64
} // __attribute__((packed))

type snap_meta_ext_obj_phys_t struct {
	Obj ObjPhysT
	Sme snap_meta_ext_t
} // __attribute__((packed))
