package pbzx

const (
	Magic     = "pbzx"
	MagicPBZM = "pbzm"

	// DefaultMaxBlockSize bounds encoded and decoded chunks and the XZ
	// dictionary.
	DefaultMaxBlockSize = 64 << 20
)

type Header struct {
	Magic       [4]byte
	BlockSize   uint64
	InflateSize uint64
	DeflateSize uint64
}
