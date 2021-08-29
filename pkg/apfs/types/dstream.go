package types

type j_phys_ext_key_t struct {
	Hdr JKeyT
}

type j_phys_ext_val_t struct {
	LenAndKind  uint64
	OwningObjID uint64
	RefConnt    int32
}

const (
	PEXT_LEN_MASK   = 0x0fffffffffffffff
	PEXT_KIND_MASK  = 0xf000000000000000
	PEXT_KIND_SHIFT = 60
)

type j_file_extent_key_t struct {
	Hdr         JKeyT
	LogicalAddr uint64
}

type j_file_extent_val_t struct {
	LenAndFlags  uint64
	PhysBlockNum uint64
	CryptoID     uint64
}

const (
	J_FILE_EXTENT_LEN_MASK   = 0x00ffffffffffffff
	J_FILE_EXTENT_FLAG_MASK  = 0xff00000000000000
	J_FILE_EXTENT_FLAG_SHIFT = 56
)

type j_dstream_id_key_t struct {
	Hdr JKeyT
}

type j_dstream_id_val_t struct {
	RefConnt uint32
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
