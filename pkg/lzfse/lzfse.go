package lzfse

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	//  Parameters controlling details of the LZ-style match search. These values
	//  may be modified to fine tune compression ratio vs. encoding speed, while
	//  keeping the compressed format compatible with LZFSE. Note that
	//  modifying them will also change the amount of work space required by
	//  the encoder. The values here are those used in the compression library
	//  on iOS and OS X.

	//  Number of bits for hash function to produce. Should be in the range
	//  [10, 16]. Larger values reduce the number of false-positive found during
	//  the match search, and expand the history table, which may allow additional
	//  matches to be found, generally improving the achieved compression ratio.
	//  Larger values also increase the workspace size, and make it less likely
	//  that the history table will be present in cache, which reduces performance.
	LZFSE_ENCODE_HASH_BITS = 14

	//  Number of positions to store for each line in the history table. May
	//  be either 4 or 8. Using 8 doubles the size of the history table, which
	//  increases the chance of finding matches (thus improving compression ratio),
	//  but also increases the workspace size.
	LZFSE_ENCODE_HASH_WIDTH = 4

	//  Match length in bytes to cause immediate emission. Generally speaking,
	//  LZFSE maintains multiple candidate matches and waits to decide which match
	//  to emit until more information is available. When a match exceeds this
	//  threshold, it is emitted immediately. Thus, smaller values may give
	//  somewhat better performance, and larger values may give somewhat better
	//  compression ratios.
	LZFSE_ENCODE_GOOD_MATCH = 40

	//  When the source buffer is very small, LZFSE doesn't compress as well as
	//  some simpler algorithms. To maintain reasonable compression for these
	//  cases, we transition to use LZVN instead if the size of the source buffer
	//  is below this threshold.
	LZFSE_ENCODE_LZVN_THRESHOLD = 4096
)

const (
	LZFSE_ENCODE_HASH_VALUES     = (1 << LZFSE_ENCODE_HASH_BITS)
	LZFSE_ENCODE_L_SYMBOLS       = 20
	LZFSE_ENCODE_M_SYMBOLS       = 20
	LZFSE_ENCODE_D_SYMBOLS       = 64
	LZFSE_ENCODE_LITERAL_SYMBOLS = 256
	LZFSE_ENCODE_L_STATES        = 64
	LZFSE_ENCODE_M_STATES        = 64
	LZFSE_ENCODE_D_STATES        = 256
	LZFSE_ENCODE_LITERAL_STATES  = 1024
	LZFSE_MATCHES_PER_BLOCK      = 10000
	LZFSE_LITERALS_PER_BLOCK     = (4 * LZFSE_MATCHES_PER_BLOCK)
)

type fseBitCount int32

// FseInStream64 object representing an input stream.
type FseInStream64 struct {
	accum       uint64      // Input bits
	accum_nbits fseBitCount // Number of valid bits in ACCUM, other bits are 0
}

// fse_value_decoder_entry entry for one state in the value decoder table (64b).
type fse_value_decoder_entry struct {
	total_bits uint8 // state bits + extra value bits = shift for next decode
	value_bits uint8 // extra value bits
	delta      int16 // state base (delta)
	vbase      int32 // value base
}

type fse_in_stream FseInStream64

// lzfse_compressed_block_decoder_state decoder state object for lzfse compressed blocks.
type lzfse_compressed_block_decoder_state struct {
	//  Number of matches remaining in the block.
	n_matches uint32
	//  Number of bytes used to encode L, M, D triplets for the block.
	n_lmd_payload_bytes uint32
	//  Pointer to the next literal to emit.
	current_literal *uint8
	//  L, M, D triplet for the match currently being emitted. This is used only
	//  if we need to restart after reaching the end of the destination buffer in
	//  the middle of a literal or match.
	l_value int32
	m_value int32
	d_value int32
	//  FSE stream object.
	lmd_in_stream fse_in_stream
	//  Offset of L,M,D encoding in the input buffer. Because we read through an
	//  FSE stream *backwards* while decoding, this is decremented as we move
	//  through a block.
	lmd_in_buf uint32
	//  The current state of the L, M, and D FSE decoders.
	l_state uint16
	m_state uint16
	d_state uint16
	//  Internal FSE decoder tables for the current block. These have
	//  alignment forced to 8 bytes to guarantee that a single state's
	//  entry cannot span two cachelines.
	l_decoder       [LZFSE_ENCODE_L_STATES]fse_value_decoder_entry //__attribute__((__aligned__(8)))
	m_decoder       [LZFSE_ENCODE_M_STATES]fse_value_decoder_entry //__attribute__((__aligned__(8)))
	d_decoder       [LZFSE_ENCODE_D_STATES]fse_value_decoder_entry //__attribute__((__aligned__(8)))
	literal_decoder [LZFSE_ENCODE_LITERAL_STATES]int32
	//  The literal stream for the block, plus padding to allow for faster copy
	//  operations.
	literals [LZFSE_LITERALS_PER_BLOCK + 64]uint8
}

//  Decoder state object for uncompressed blocks.
type uncompressed_block_decoder_state struct {
	n_raw_bytes uint32
}

// lzvn_compressed_block_decoder_state decoder state object for lzvn-compressed blocks.
type lzvn_compressed_block_decoder_state struct {
	n_raw_bytes     uint32
	n_payload_bytes uint32
	d_prev          uint32
}

type lzfse_decoder_state struct {
	//  Pointer to next byte to read from source buffer (this is advanced as we
	//  decode src_begin describe the buffer and do not change).
	src []byte
	//  Pointer to first byte of source buffer.
	src_begin int
	//  Pointer to one byte past the end of the source buffer.
	src_end int
	//  Pointer to the next byte to write to destination buffer (this is advanced
	//  as we decode dst_begin and dst_end describe the buffer and do not change).
	dst []byte
	//  Pointer to first byte of destination buffer.
	dst_begin int
	//  Pointer to one byte past the end of the destination buffer.
	dst_end int
	//  1 if we h ave reached the end of the stream, 0 otherwise.
	end_of_stream int
	//  magic number of the current block if we are within a block,
	//  LZFSE_NO_BLOCK_MAGIC otherwise.
	block_magic                  uint32
	compressed_lzfse_block_state lzfse_compressed_block_decoder_state
	compressed_lzvn_block_state  lzvn_compressed_block_decoder_state
	uncompressed_block_state     uncompressed_block_decoder_state
}

const (
	// Block header objects
	LZFSE_NO_BLOCK_MAGIC             = 0x00000000 // 0    (invalid)
	LZFSE_ENDOFSTREAM_BLOCK_MAGIC    = 0x24787662 // bvx$ (end of stream)
	LZFSE_UNCOMPRESSED_BLOCK_MAGIC   = 0x2d787662 // bvx- (raw data)
	LZFSE_COMPRESSEDV1_BLOCK_MAGIC   = 0x31787662 // bvx1 (lzfse compressed, uncompressed tables)
	LZFSE_COMPRESSEDV2_BLOCK_MAGIC   = 0x32787662 // bvx2 (lzfse compressed, compressed tables)
	LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC = 0x6e787662 // bvxn (lzvn compressed)
)

// Decode decodes an encoded lzfse buffer
func Decode(srcBuffer []byte) ([]byte, error) {
	out := make([]byte, len(srcBuffer), len(srcBuffer)*4)
	// scratch := make([]byte, binary.Size(lzfse_decoder_state{}))

	// Initialize state
	s := &lzfse_decoder_state{
		src:       srcBuffer,
		src_begin: 0,
		src_end:   len(srcBuffer),
		dst:       out,
		dst_begin: 0,
		dst_end:   len(out),
	}

	r := bytes.NewReader(srcBuffer)

	// Decode
	for {
		switch s.block_magic {
		case LZFSE_NO_BLOCK_MAGIC:
			fmt.Println("LZFSE_NO_BLOCK_MAGIC")
			if err := binary.Read(r, binary.LittleEndian, s.block_magic); err != nil {
				return nil, err
			}
			if s.block_magic == LZFSE_ENDOFSTREAM_BLOCK_MAGIC {
				return out, nil
			}
			if s.block_magic == LZFSE_UNCOMPRESSED_BLOCK_MAGIC {
			}
			if s.block_magic == LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC {
			}
			if s.block_magic == LZFSE_COMPRESSEDV1_BLOCK_MAGIC ||
				s.block_magic == LZFSE_COMPRESSEDV2_BLOCK_MAGIC {
				// Decode compressed headers
				if s.block_magic == LZFSE_COMPRESSEDV2_BLOCK_MAGIC {
				}
				break
			}
			// Here we have an invalid magic number
			return nil, fmt.Errorf("LZFSE_STATUS_ERROR")
		case LZFSE_UNCOMPRESSED_BLOCK_MAGIC:
			fmt.Println("LZFSE_UNCOMPRESSED_BLOCK_MAGIC")
			break
		case LZFSE_COMPRESSEDV1_BLOCK_MAGIC:
		case LZFSE_COMPRESSEDV2_BLOCK_MAGIC:
			fmt.Println("LZFSE_COMPRESSEDV1_BLOCK_MAGIC || LZFSE_COMPRESSEDV2_BLOCK_MAGIC")
			break
		case LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC:
			fmt.Println("LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC")
			// Run LZVN decoder
			//   lzvn_decode(&dstate)
			break
		default:
			return nil, fmt.Errorf("LZFSE_STATUS_ERROR")
		}
	}
	// status := lzfse_decode(s)
	// if (status == LZFSE_STATUS_DST_FULL){
	// 	return dst_size
	// }

	// if (status != LZFSE_STATUS_OK) {
	// 		return 0
	// }

	// return out, nil
}
