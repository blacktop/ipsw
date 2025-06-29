package comp

// Algorithm is the compression algorithm type
type Algorithm uint

const (
	LZ4         Algorithm = 0x100
	LZ4_RAW     Algorithm = 0x101
	ZLIB        Algorithm = 0x205
	LZMA        Algorithm = 0x306
	LZFSE       Algorithm = 0x801
	LZFSE_IBOOT Algorithm = 0x891
	LZBITMAP    Algorithm = 0x702
	BROTLI      Algorithm = 0xB02
)

// Compress compresses the given data using the specified algorithm.
func Compress(data []byte, algorithm Algorithm) ([]byte, error) {
	return compress(data, algorithm)
}

// Decompress decompresses the given data using the specified algorithm.
func Decompress(data []byte, algorithm Algorithm) ([]byte, error) {
	return decompress(data, algorithm)
}
