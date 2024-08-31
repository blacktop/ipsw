package pbzx

type Header struct {
	Magic       [4]byte
	BlockSize   uint64
	InflateSize uint64
	DeflateSize uint64
}
