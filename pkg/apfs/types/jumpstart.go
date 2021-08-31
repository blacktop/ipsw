package types

/** `nx_efi_jumpstart_t` **/

type nx_efi_jumpstart_t struct {
	Obj        ObjPhysT
	Magic      uint32
	Version    uint32
	EfiFileLen uint32
	NumExtents uint32
	Reserved   [16]uint64
	RecExtents []prange
}

const (
	NX_EFI_JUMPSTART_MAGIC   = "RDSJ"
	NX_EFI_JUMPSTART_VERSION = 1

	/** Partition UUIDs **/

	APFS_GPT_PARTITION_UUID = "7C3457EF-0000-11AA-AA11-00306543ECAC"
)
