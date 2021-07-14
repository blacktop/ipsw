package types

type xf_blob_t struct {
	XfNumExts  uint16
	XfUsedData uint16
	XfData     []byte
}

type x_field_t struct {
	XType  xfType
	XFlags xfFlag
	XSize  uint16
}

type xfType byte
type xfFlag byte

const (
	/** Extended-Field Types **/
	DREC_EXT_TYPE_SIBLING_ID = 1

	INO_EXT_TYPE_SNAP_XID          xfType = 1
	INO_EXT_TYPE_DELTA_TREE_OID    xfType = 2
	INO_EXT_TYPE_DOCUMENT_ID       xfType = 3
	INO_EXT_TYPE_NAME              xfType = 4
	INO_EXT_TYPE_PREV_FSIZE        xfType = 5
	INO_EXT_TYPE_RESERVED_6        xfType = 6
	INO_EXT_TYPE_FINDER_INFO       xfType = 7
	INO_EXT_TYPE_DSTREAM           xfType = 8
	INO_EXT_TYPE_RESERVED_9        xfType = 9
	INO_EXT_TYPE_DIR_STATS_KEY     xfType = 10
	INO_EXT_TYPE_FS_UUID           xfType = 11
	INO_EXT_TYPE_RESERVED_12       xfType = 12
	INO_EXT_TYPE_SPARSE_BYTES      xfType = 13
	INO_EXT_TYPE_RDEV              xfType = 14
	INO_EXT_TYPE_PURGEABLE_FLAGS   xfType = 15
	INO_EXT_TYPE_ORIG_SYNC_ROOT_ID xfType = 16

	/** Extended-Field Flags **/
	XF_DATA_DEPENDENT   xfFlag = 0x0001
	XF_DO_NOT_COPY      xfFlag = 0x0002
	XF_RESERVED_4       xfFlag = 0x0004
	XF_CHILDREN_INHERIT xfFlag = 0x0008
	XF_USER_FIELD       xfFlag = 0x0010
	XF_SYSTEM_FIELD     xfFlag = 0x0020
	XF_RESERVED_40      xfFlag = 0x0040
	XF_RESERVED_80      xfFlag = 0x0080
)
