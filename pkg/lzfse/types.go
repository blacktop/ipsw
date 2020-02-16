package lzfse

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

	LZFSE_ENCODE_L_SYMBOLS_MAX       = 20
	LZFSE_ENCODE_M_SYMBOLS_MAX       = LZFSE_ENCODE_L_SYMBOLS + LZFSE_ENCODE_M_SYMBOLS
	LZFSE_ENCODE_D_SYMBOLS_MAX       = LZFSE_ENCODE_L_SYMBOLS + LZFSE_ENCODE_M_SYMBOLS + LZFSE_ENCODE_D_SYMBOLS
	LZFSE_ENCODE_LITERAL_SYMBOLS_MAX = LZFSE_ENCODE_L_SYMBOLS + LZFSE_ENCODE_M_SYMBOLS + LZFSE_ENCODE_D_SYMBOLS + LZFSE_ENCODE_LITERAL_SYMBOLS

	LZFSE_ENCODE_L_STATES       = 64
	LZFSE_ENCODE_M_STATES       = 64
	LZFSE_ENCODE_D_STATES       = 256
	LZFSE_ENCODE_LITERAL_STATES = 1024
	LZFSE_MATCHES_PER_BLOCK     = 10000
	LZFSE_LITERALS_PER_BLOCK    = (4 * LZFSE_MATCHES_PER_BLOCK)
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

// compressedBlockHeaderV1 block header with uncompressed tables.
type compressedBlockHeaderV1 struct {
	//  Magic number, always LZFSE_COMPRESSEDV1_BLOCK_MAGIC.
	Magic uint32
	//  Number of decoded (output) bytes in block.
	NRawBytes uint32
	//  Number of encoded (source) bytes in block.
	NPayloadBytes uint32
	//  Number of literal bytes output by block (*not* the number of literals).
	NLiterals uint32
	//  Number of matches in block (which is also the number of literals).
	NMatches uint32
	//  Number of bytes used to encode literals.
	NLiteralPayloadBytes uint32
	//  Number of bytes used to encode matches.
	NLmdPayloadBytes uint32

	//  Final encoder states for the block, which will be the initial states for
	//  the decoder:
	//  Final accum_nbits for literals stream.
	LiteralBits int32
	//  There are four interleaved streams of literals, so there are four final
	//  states.
	LiteralState [4]uint16
	//  accum_nbits for the l, m, d stream.
	LmdBits int32
	//  Final L (literal length) state.
	LState uint16
	//  Final M (match length) state.
	MState uint16
	//  Final D (match distance) state.
	DState uint16

	//  Normalized frequency tables for each stream. Sum of values in each
	//  array is the number of states.
	LFreq       [LZFSE_ENCODE_L_SYMBOLS]uint16
	MFreq       [LZFSE_ENCODE_M_SYMBOLS]uint16
	DFreq       [LZFSE_ENCODE_D_SYMBOLS]uint16
	LiteralFreq [LZFSE_ENCODE_LITERAL_SYMBOLS]uint16
}

/* compressedBlockHeaderV2 block header with compressed tables. Note that because
 *  freq[] is compressed, the structure-as-stored-in-the-stream is *truncated*;
 *  we only store the used bytes of freq[]. This means that some extra care must
 *  be taken when reading one of these headers from the stream. */
type compressedBlockHeaderV2 struct {
	//  Magic number, always LZFSE_COMPRESSEDV2_BLOCK_MAGIC.
	Magic uint32
	//  Number of decoded (output) bytes in block.
	NRawBytes uint32
	//  The fields n_payload_bytes ... d_state from the
	//  lzfse_compressed_block_header_v1 object are packed into three 64-bit
	//  fields in the compressed header, as follows:
	//
	//    offset  bits  value
	//    0       20    n_literals
	//    20      20    n_literal_payload_bytes
	//    40      20    n_matches
	//    60      3     literal_bits
	//    63      1     --- unused ---
	//
	//    0       10    literal_state[0]
	//    10      10    literal_state[1]
	//    20      10    literal_state[2]
	//    30      10    literal_state[3]
	//    40      20    n_lmd_payload_bytes
	//    60      3     lmd_bits
	//    63      1     --- unused ---
	//
	//    0       32    header_size (total header size in bytes; this does not
	//                  correspond to a field in the uncompressed header version,
	//                  but is required; we wouldn't know the size of the
	//                  compresssed header otherwise.
	//    32      10    l_state
	//    42      10    m_state
	//    52      10    d_state
	//    62      2     --- unused ---
	PackedFields [3]uint64
	//  Variable size freq tables, using a Huffman-style fixed encoding.
	//  Size allocated here is an upper bound (all values stored on 16 bits).
	Freq [2 * (LZFSE_ENCODE_L_SYMBOLS + LZFSE_ENCODE_M_SYMBOLS +
		LZFSE_ENCODE_D_SYMBOLS + LZFSE_ENCODE_LITERAL_SYMBOLS)]uint8
}

var lExtraBits = [LZFSE_ENCODE_L_SYMBOLS]uint8{
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 5, 8,
}

var lBaseValue = [LZFSE_ENCODE_L_SYMBOLS]int32{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 28, 60,
}

var mExtraBits = [LZFSE_ENCODE_M_SYMBOLS]uint8{
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 5, 8, 11,
}

var mBaseValue = [LZFSE_ENCODE_M_SYMBOLS]int32{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 24, 56, 312,
}

var dExtraBits = [LZFSE_ENCODE_D_SYMBOLS]uint8{
	0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
	4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7,
	8, 8, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 11, 11, 11, 11,
	12, 12, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15,
}

var dBaseValue = [LZFSE_ENCODE_D_SYMBOLS]int32{
	0, 1, 2, 3, 4, 6, 8, 10, 12, 16,
	20, 24, 28, 36, 44, 52, 60, 76, 92, 108,
	124, 156, 188, 220, 252, 316, 380, 444, 508, 636,
	764, 892, 1020, 1276, 1532, 1788, 2044, 2556, 3068, 3580,
	4092, 5116, 6140, 7164, 8188, 10236, 12284, 14332, 16380, 20476,
	24572, 28668, 32764, 40956, 49148, 57340, 65532, 81916, 98300, 114684,
	131068, 163836, 196604, 229372,
}

func getField(v uint64, offset, nbits int) uint32 {
	if nbits == 32 {
		return uint32(v >> offset)
	}
	return uint32((v >> offset) & ((1 << nbits) - 1))
}
