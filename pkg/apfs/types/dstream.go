package types

import "fmt"

type j_phys_ext_key_t struct {
	Hdr JKeyT
}

const (
	PEXT_LEN_MASK   = 0x0fffffffffffffff
	PEXT_KIND_MASK  = 0xf000000000000000
	PEXT_KIND_SHIFT = 60
)

type j_phys_ext_val_t struct {
	LenAndKind  uint64 // A bit field that contains the length of the extent and its kind.
	OwningObjID uint64 // The identifier of the file system record thatʼs using this extent.
	RefCount    int32  // The reference count.
}

func (v j_phys_ext_val_t) Length() uint64 {
	return v.LenAndKind & PEXT_LEN_MASK
}

func (v j_phys_ext_val_t) Kind() j_obj_kinds {
	return j_obj_kinds((v.LenAndKind & PEXT_KIND_MASK) >> PEXT_KIND_SHIFT)
}

func (v j_phys_ext_val_t) String() string {
	return fmt.Sprintf("kind=%s, length=%#x, owning_obj_id=%#x, ref_count=%d",
		v.Kind().String(),
		v.Length(),
		v.OwningObjID,
		v.RefCount)
}

const (
	J_FILE_EXTENT_LEN_MASK   = 0x00ffffffffffffff
	J_FILE_EXTENT_FLAG_MASK  = 0xff00000000000000
	J_FILE_EXTENT_FLAG_SHIFT = 56
)

type j_file_extent_key_t struct {
	// Hdr         JKeyT
	LogicalAddr uint64
}

type j_file_extent_val_t struct {
	LenAndFlags  uint64
	PhysBlockNum uint64
	CryptoID     uint64
}

func (v j_file_extent_val_t) Length() uint64 {
	return v.LenAndFlags & J_FILE_EXTENT_LEN_MASK
}

func (v j_file_extent_val_t) Flags() uint64 {
	return (v.LenAndFlags & J_FILE_EXTENT_FLAG_MASK) >> J_FILE_EXTENT_FLAG_SHIFT
}

func (v j_file_extent_val_t) String() string {
	return fmt.Sprintf("flags=%#x, length=%#x, phys_block_num=%#x, crypto_id=%#x",
		v.Flags(),
		v.Length(),
		v.PhysBlockNum,
		v.CryptoID)
}

type j_dstream_id_key_t struct {
	Hdr JKeyT
}

type j_dstream_id_val_t struct {
	RefCount uint32
}

func (v j_dstream_id_val_t) String() string {
	return fmt.Sprintf("ref_count=%d", v.RefCount)
}

type j_dstream_t struct {
	Size              uint64
	AllocedSize       uint64
	DefaultCryptoID   uint64
	TotalBytesWritten uint64
	TotalBytesRead    uint64
}

type j_xattr_dstream_t struct {
	XattrObjID uint64
	DStream    j_dstream_t
}
