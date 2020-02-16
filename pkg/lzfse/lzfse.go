package lzfse

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/apex/log"
)

// Decoder lzfse decoder state object
type Decoder struct {
	blockMagic uint32

	src *bytes.Reader
	dst *bytes.Buffer

	CompressedLzfseBlockState lzfseCompressedBlockDecoderState
	CompressedLzvnBlockState  lzvnCompressedBlockDecoderState
	UncompressedBlockState    uncompressedBlockDecoderState
}

// NewDecoder creates a new lzfse decoder
func NewDecoder(data []byte) *Decoder {
	return &Decoder{
		src: bytes.NewReader(data),
		dst: bytes.NewBuffer(make([]byte, 4*len(data))),
	}
}

/* decodeV1FreqValue decode an entry value from next bits of stream.
 * Return value, and nbits, the number of bits to consume (starting with LSB). */
func decodeV1FreqValue(bits uint32) (uint16, int) {
	freqNbitsTable := [32]int8{
		2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14,
		2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14,
	}
	freqValueTable := [32]int8{
		0, 2, 1, 4, 0, 3, 1, -1, 0, 2, 1, 5, 0, 3, 1, -1,
		0, 2, 1, 6, 0, 3, 1, -1, 0, 2, 1, 7, 0, 3, 1, -1,
	}

	b := bits & 31 // lower 5 bits
	n := int(freqNbitsTable[b])

	// Special cases for > 5 bits encoding
	if n == 8 {
		return uint16(8 + (bits>>4)&0xf), n
	}
	if n == 14 {
		return uint16(24 + (bits>>4)&0x3ff), n
	}

	// <= 5 bits encoding from table
	return uint16(freqValueTable[b]), n
}

// decodeV1 decode all fields from a compressedBlockHeaderV2 to a compressedBlockHeaderV1.
func decodeV1(out *compressedBlockHeaderV1, in compressedBlockHeaderV2) error {

	v0 := in.PackedFields[0]
	v1 := in.PackedFields[1]
	v2 := in.PackedFields[2]

	out.Magic = LZFSE_COMPRESSEDV1_BLOCK_MAGIC
	out.NRawBytes = in.NRawBytes

	// Literal state
	out.NLiterals = getField(v0, 0, 20)
	out.NLiteralPayloadBytes = getField(v0, 20, 20)
	out.LiteralBits = int32(getField(v0, 60, 3) - 7)
	out.LiteralState[0] = uint16(getField(v1, 0, 10))
	out.LiteralState[1] = uint16(getField(v1, 10, 10))
	out.LiteralState[2] = uint16(getField(v1, 20, 10))
	out.LiteralState[3] = uint16(getField(v1, 30, 10))

	// L,M,D state
	out.NMatches = getField(v0, 40, 20)
	out.NLmdPayloadBytes = getField(v1, 40, 20)
	out.LmdBits = int32(getField(v1, 60, 3) - 7)
	out.LState = uint16(getField(v2, 32, 10))
	out.MState = uint16(getField(v2, 42, 10))
	out.DState = uint16(getField(v2, 52, 10))

	// Total payload size
	out.NPayloadBytes = out.NLiteralPayloadBytes + out.NLmdPayloadBytes

	// Freq tables
	srcStart := uint32(0)
	srcEnd := getField(v2, 0, 32) - 32 // first byte after header
	var accum uint32
	var accumNbits int

	// No freq tables?
	if srcEnd == srcStart {
		return nil // OK, freq tables were omitted
	}

	for i := 0; i < (LZFSE_ENCODE_L_SYMBOLS + LZFSE_ENCODE_M_SYMBOLS +
		LZFSE_ENCODE_D_SYMBOLS + LZFSE_ENCODE_LITERAL_SYMBOLS); i++ {
		// Refill accum, one byte at a time, until we reach end of header, or accum is full
		for srcStart < srcEnd && accumNbits+8 <= 32 {
			accum |= uint32(in.Freq[srcStart]) << accumNbits
			accumNbits += 8
			srcStart++
		}

		// Decode and store value
		nbits := 0
		switch idx := i; {
		case idx < LZFSE_ENCODE_L_SYMBOLS_MAX:
			out.LFreq[idx], nbits = decodeV1FreqValue(accum)
		case LZFSE_ENCODE_L_SYMBOLS_MAX <= idx && idx < LZFSE_ENCODE_M_SYMBOLS_MAX:
			out.MFreq[idx-LZFSE_ENCODE_L_SYMBOLS_MAX], nbits = decodeV1FreqValue(accum)
		case LZFSE_ENCODE_M_SYMBOLS_MAX <= idx && idx < LZFSE_ENCODE_D_SYMBOLS_MAX:
			out.DFreq[idx-LZFSE_ENCODE_M_SYMBOLS_MAX], nbits = decodeV1FreqValue(accum)
		case LZFSE_ENCODE_D_SYMBOLS_MAX <= idx && idx < LZFSE_ENCODE_LITERAL_SYMBOLS_MAX:
			out.LiteralFreq[idx-LZFSE_ENCODE_D_SYMBOLS_MAX], nbits = decodeV1FreqValue(accum)
		}

		if nbits > accumNbits {
			return fmt.Errorf("failed")
		}

		// Consume nbits bits
		accum >>= nbits
		accumNbits -= nbits
	}

	if accumNbits >= 8 || srcStart != srcEnd {
		return fmt.Errorf("failed to end up exactly at the end of header, with less than 8 bits in accumulator")
	}

	return nil
}

func (s *Decoder) decodeLMD() error {
	lState := s.CompressedLzfseBlockState.LState
	mState := s.CompressedLzfseBlockState.MState
	dState := s.CompressedLzfseBlockState.DState
	in := s.CompressedLzfseBlockState.LmdInStream
	//   const uint8_t *src_start = s->src_begin;
	//   const uint8_t *src = s->src +  s.CompressedLzfseBlockState->lmd_in_buf;
	lit := s.CompressedLzfseBlockState.CurrentLiteral
	//   uint8_t *dst = s->dst;
	symbols := s.CompressedLzfseBlockState.NMatches
	l := s.CompressedLzfseBlockState.LValue
	m := s.CompressedLzfseBlockState.MValue
	d := s.CompressedLzfseBlockState.DValue

	// assert(l_state < LZFSE_ENCODE_L_STATES)
	// assert(m_state < LZFSE_ENCODE_M_STATES)
	// assert(d_state < LZFSE_ENCODE_D_STATES)

	//  Number of bytes remaining in the destination buffer, minus 32 to
	//  provide a margin of safety for using overlarge copies on the fast path.
	//  This is a signed quantity, and may go negative when we are close to the
	//  end of the buffer.  That's OK; we're careful about how we handle it
	//  in the slow-and-careful match execution path.
	//   ptrdiff_t remaining_bytes = s->dst_end - dst - 32; // TODO

	//  If L or M is non-zero, that means that we have already started decoding
	//  this block, and that we needed to interrupt decoding to get more space
	//  from the caller.  There's a pending L, M, D triplet that we weren't
	//  able to completely process.  Jump ahead to finish executing that symbol
	//  before decoding new values.
	if l > 0 || m > 0 {
		goto ExecuteMatch
	}

	for symbols > 0 {
		//  Decode the next L, M, D symbol from the input stream.
		res := fseInCheckedFlush(&in, &src, src_start)
		if res > 0 {
			return fmt.Errorf("LZFSE_STATUS_ERROR")
		}
		l = fseValueDecode(&lState, s.CompressedLzfseBlockState.LDecoder[:], &in)
		// assert(l_state < LZFSE_ENCODE_L_STATES)
		// TODO
		// if (lit + l) >= (s.CompressedLzfseBlockState.Literals + LZFSE_LITERALS_PER_BLOCK + 64) {
		// 	return fmt.Errorf("LZFSE_STATUS_ERROR")
		// }

		// res = fse_in_flush2(&in, &src, src_start);
		// if (res) {
		//   return LZFSE_STATUS_ERROR;
		// }

		m = fseValueDecode(&mState, s.CompressedLzfseBlockState.MDecoder[:], &in)
		// assert(m_state < LZFSE_ENCODE_M_STATES)

		// res = fse_in_flush2(&in, &src, src_start);
		// if (res) {
		//   return LZFSE_STATUS_ERROR;
		// }

		newD := fseValueDecode(&dState, s.CompressedLzfseBlockState.DDecoder[:], &in)
		// assert(d_state < LZFSE_ENCODE_D_STATES)

		if newD > 0 {
			d = newD
		}

		symbols--
	ExecuteMatch:
		fmt.Println("kill me")

	}

	return nil
}

// Decode decodes an encoded lzfse buffer
func (s *Decoder) Decode() ([]byte, error) {

	for {
		switch s.blockMagic {
		case LZFSE_NO_BLOCK_MAGIC:
			log.Debug("LZFSE_NO_BLOCK_MAGIC")
			if err := binary.Read(s.src, binary.LittleEndian, &s.blockMagic); err != nil {
				return nil, err
			}
			s.src.Seek(int64(-binary.Size(s.blockMagic)), io.SeekCurrent)

			if s.blockMagic == LZFSE_ENDOFSTREAM_BLOCK_MAGIC {
				log.Debug("LZFSE_ENDOFSTREAM_BLOCK_MAGIC")
				return s.dst.Bytes(), nil
			}
			if s.blockMagic == LZFSE_UNCOMPRESSED_BLOCK_MAGIC {
				log.Debug("LZFSE_UNCOMPRESSED_BLOCK_MAGIC")
				return nil, fmt.Errorf("not implimented")
			}
			if s.blockMagic == LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC {
				log.Debug("LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC")
				return nil, fmt.Errorf("not implimented")
			}
			if s.blockMagic == LZFSE_COMPRESSEDV1_BLOCK_MAGIC ||
				s.blockMagic == LZFSE_COMPRESSEDV2_BLOCK_MAGIC {
				log.Debug("LZFSE_COMPRESSEDV1_BLOCK_MAGIC || LZFSE_COMPRESSEDV2_BLOCK_MAGIC")
				var header1 compressedBlockHeaderV1
				var header2 compressedBlockHeaderV2
				// Decode compressed headers
				if s.blockMagic == LZFSE_COMPRESSEDV2_BLOCK_MAGIC {
					log.Debug("LZFSE_COMPRESSEDV2_BLOCK_MAGIC")
					if err := binary.Read(s.src, binary.LittleEndian, &header2); err != nil {
						return nil, err
					}
					err := decodeV1(&header1, header2)
					if err != nil {
						return nil, err
					}
					// Skip header
					s.src.Seek(int64(binary.Size(compressedBlockHeaderV1{})), io.SeekCurrent)
				} else {
					// This should happen
					log.Error("Not LZFSE_COMPRESSEDV2_BLOCK_MAGIC")
					if err := binary.Read(s.src, binary.LittleEndian, &header1); err != nil {
						return nil, err
					}
				}

				// Setup state for compressed V1 block from header
				s.CompressedLzfseBlockState.NLmdPayloadBytes = header1.NLmdPayloadBytes
				s.CompressedLzfseBlockState.NMatches = header1.NMatches
				fseInitDecoderTable(
					LZFSE_ENCODE_LITERAL_STATES,
					LZFSE_ENCODE_LITERAL_SYMBOLS,
					header1.LiteralFreq,
					s.CompressedLzfseBlockState.LiteralDecoder,
				)
				s.CompressedLzfseBlockState.LDecoder = fseInitValueDecoderTable(
					LZFSE_ENCODE_L_STATES, LZFSE_ENCODE_L_SYMBOLS, header1.LFreq[:],
					lExtraBits[:], lBaseValue[:], s.CompressedLzfseBlockState.LDecoder[:])
				s.CompressedLzfseBlockState.MDecoder = fseInitValueDecoderTable(
					LZFSE_ENCODE_M_STATES, LZFSE_ENCODE_M_SYMBOLS, header1.MFreq[:],
					mExtraBits[:], mBaseValue[:], s.CompressedLzfseBlockState.MDecoder[:])
				s.CompressedLzfseBlockState.DDecoder = fseInitValueDecoderTable(
					LZFSE_ENCODE_D_STATES, LZFSE_ENCODE_D_SYMBOLS, header1.DFreq[:],
					dExtraBits[:], dBaseValue[:], s.CompressedLzfseBlockState.DDecoder[:])

				// Decode literals
				var in fseInStream
				//   const uint8_t *buf_start = s->src_begin
				s.src.Seek(int64(header1.NLiteralPayloadBytes), io.SeekCurrent) // skip literal payload
				//   const uint8_t *buf = s->src; // read bits backwards from the end
				if err := fseInCheckedInit(&in, header1.LiteralBits, &buf, buf_start); err != nil {
					return nil, fmt.Errorf("LZFSE_STATUS_ERROR")
				}

				state0 := header1.LiteralState[0]
				state1 := header1.LiteralState[1]
				state2 := header1.LiteralState[2]
				state3 := header1.LiteralState[3]

				for i := uint32(0); i < header1.NLiterals; i += 4 { // n_literals is multiple of 4
					if err := fseInCheckedFlush(&in, &buf, buf_start); err != nil {
						return nil, fmt.Errorf("LZFSE_STATUS_ERROR") // [57, 64] bits
					}
					s.CompressedLzfseBlockState.Literals[i+0] =
						fseDecode(&state0, s.CompressedLzfseBlockState.LiteralDecoder, &in) // 10b max
					s.CompressedLzfseBlockState.Literals[i+1] =
						fseDecode(&state1, s.CompressedLzfseBlockState.LiteralDecoder, &in) // 10b max
					s.CompressedLzfseBlockState.Literals[i+2] =
						fseDecode(&state2, s.CompressedLzfseBlockState.LiteralDecoder, &in) // 10b max
					s.CompressedLzfseBlockState.Literals[i+3] =
						fseDecode(&state3, s.CompressedLzfseBlockState.LiteralDecoder, &in) // 10b max
				}
				s.CompressedLzfseBlockState.CurrentLiteral = s.CompressedLzfseBlockState.Literals

				// SRC is not incremented to skip the LMD payload, since we need it
				// during block decode.
				// We will increment SRC at the end of the block only after this point.

				// Initialize the L,M,D decode stream, do not start decoding matches
				// yet, and store decoder state
				var in2 fseInStream
				// read bits backwards from the end
				// const uint8_t *buf = s->src + header1.NLmdPayloadBytes
				if err := fseInCheckedInit(&in2, header1.LmdBits, &buf, buf_start); err != nil {
					return nil, fmt.Errorf("LZFSE_STATUS_ERROR")
				}

				s.CompressedLzfseBlockState.LState = header1.LState
				s.CompressedLzfseBlockState.MState = header1.MState
				s.CompressedLzfseBlockState.DState = header1.DState
				//  s.CompressedLzfseBlockState.LmdInBuf = (uint32_t)(buf - s->src)
				s.CompressedLzfseBlockState.LValue = 0
				s.CompressedLzfseBlockState.MValue = 0
				//  Initialize D to an illegal value so we can't erroneously use
				//  an uninitialized "previous" value.
				s.CompressedLzfseBlockState.DValue = -1
				s.CompressedLzfseBlockState.LmdInStream = in2

				break
			}
			// Here we have an invalid magic number
			return nil, fmt.Errorf("LZFSE_STATUS_ERROR")
		case LZFSE_UNCOMPRESSED_BLOCK_MAGIC:
			log.Debug("LZFSE_UNCOMPRESSED_BLOCK_MAGIC")
			return nil, fmt.Errorf("not implimented")
			break
		case LZFSE_COMPRESSEDV1_BLOCK_MAGIC:
		case LZFSE_COMPRESSEDV2_BLOCK_MAGIC:
			log.Debug("LZFSE_COMPRESSEDV1_BLOCK_MAGIC || LZFSE_COMPRESSEDV2_BLOCK_MAGIC")
			// Require the entire LMD payload to be in SRC
			// if (s->src_end <= s->src ||
			// 	s.CompressedLzfseBlockState.n_lmd_payload_bytes > (size_t)(s->src_end - s->src)) {
			// 		return nil, fmt.Errorf("LZFSE_STATUS_SRC_EMPTY")
			// 	}

			err := s.decodeLMD()
			if err != nil {
				return nil, err
			}

			s.blockMagic = LZFSE_NO_BLOCK_MAGIC
			s.src.Seek(int64(s.CompressedLzfseBlockState.NLmdPayloadBytes), io.SeekCurrent) // to next block
			break
		case LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC:
			log.Debug("LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC")
			return nil, fmt.Errorf("not implimented")
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
