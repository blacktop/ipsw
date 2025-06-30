package comp

import "fmt"

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

func (a Algorithm) String() string {
	switch a {
	case LZ4:
		return "lz4"
	case LZ4_RAW:
		return "lz4_raw"
	case ZLIB:
		return "zlib"
	case LZMA:
		return "lzma"
	case LZFSE:
		return "lzfse"
	case LZFSE_IBOOT:
		return "lzfse_iboot"
	case LZBITMAP:
		return "lzbitmap"
	case BROTLI:
		return "brotli"
	default:
		return fmt.Sprintf("unknown(%d)", a)
	}
}

func Lookup(name string) (Algorithm, error) {
	switch name {
	case "lz4":
		return LZ4, nil
	case "lz4_raw":
		return LZ4_RAW, nil
	case "zlib":
		return ZLIB, nil
	case "lzma":
		return LZMA, nil
	case "lzfse":
		return LZFSE, nil
	case "lzfse_iboot":
		return LZFSE_IBOOT, nil
	case "lzbitmap":
		return LZBITMAP, nil
	case "brotli":
		return BROTLI, nil
	default:
		return 0, fmt.Errorf("unknown compression algorithm: %s", name)
	}
}

func Algorithms() []string {
	return []string{
		LZ4.String(),
		LZ4_RAW.String(),
		ZLIB.String(),
		LZMA.String(),
		LZFSE.String(),
		LZFSE_IBOOT.String(),
		LZBITMAP.String(),
		BROTLI.String(),
	}
}

// Compress compresses the given data using the specified algorithm.
func Compress(data []byte, algorithm Algorithm) ([]byte, error) {
	return compress(data, algorithm)
}

// Decompress decompresses the given data using the specified algorithm.
func Decompress(data []byte, algorithm Algorithm) ([]byte, error) {
	return decompress(data, algorithm)
}
