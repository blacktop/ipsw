package lzfse

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/apex/log"
	"github.com/pkg/errors"
)

// Decoder lzfse_decoder_state object
type Decoder struct {
	blockMagic magic

	src    *bytes.Reader
	dst    bytes.Buffer
	dstIdx int32

	CompressedLzfseBlockState lzfseCompressedBlockDecoderState
	CompressedLzvnBlockState  lzvnCompressedBlockDecoderState
	UncompressedBlockState    uncompressedBlockDecoderState
}

// NewDecoder creates a new lzfse decoder
func NewDecoder(data []byte) *Decoder {
	var dst bytes.Buffer
	dst.Grow(4 * len(data))
	return &Decoder{
		src: bytes.NewReader(data),
		dst: dst,
	}
}

// DecodeBuffer decompresses a buffer using LZFSE.
func (s *Decoder) DecodeBuffer() ([]byte, error) {
	err := s.decode()
	if err != nil {
		return nil, err
	}
	return s.dst.Bytes(), nil
}

// decodeV1FreqValue decode an entry value from next bits of stream.
// Return value, and nbits, the number of bits to consume (starting with LSB).
func decodeV1FreqValue(bits uint32, nbits *int) uint16 {
	freqNbitsTable := [32]int8{
		2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14,
		2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14,
	}
	freqValueTable := [32]int8{
		0, 2, 1, 4, 0, 3, 1, -1, 0, 2, 1, 5, 0, 3, 1, -1,
		0, 2, 1, 6, 0, 3, 1, -1, 0, 2, 1, 7, 0, 3, 1, -1,
	}

	b := bits & 31 // lower 5 bits
	*nbits = int(freqNbitsTable[b])

	// Special cases for > 5 bits encoding
	if *nbits == 8 {
		return uint16(8 + (bits>>4)&0xf)
	}
	if *nbits == 14 {
		return uint16(24 + (bits>>4)&0x3ff)
	}

	// <= 5 bits encoding from table
	return uint16(freqValueTable[b])
}

// Extracts up to 32 bits from a 64-bit field beginning at offset, and zero-extends them to a  uint32.
// If we number the bits of  v from 0 (least significant) to 63 (most significant), the result is bits
// offset to  offset+nbits-1.
func getField(v uint64, offset, nbits int) uint32 {
	if nbits == 32 {
		return uint32(v >> offset)
	}
	return uint32((v >> offset) & ((1 << nbits) - 1))
}

// decodeV2HeaderSize returns header_size field from a compressedBlockHeaderV2.
func decodeV2HeaderSize(in compressedBlockHeaderV2) uint32 {
	return getField(in.PackedFields[2], 0, 32)
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
	out.LiteralBits = fseBitCount(getField(v0, 60, 3) - 7)
	out.LiteralState[0] = uint16(getField(v1, 0, 10))
	out.LiteralState[1] = uint16(getField(v1, 10, 10))
	out.LiteralState[2] = uint16(getField(v1, 20, 10))
	out.LiteralState[3] = uint16(getField(v1, 30, 10))

	// L,M,D state
	out.NMatches = getField(v0, 40, 20)
	out.NLmdPayloadBytes = getField(v1, 40, 20)
	out.LmdBits = fseBitCount(getField(v1, 60, 3) - 7)
	out.LState = uint16(getField(v2, 32, 10))
	out.MState = uint16(getField(v2, 42, 10))
	out.DState = uint16(getField(v2, 52, 10))

	// Total payload size
	out.NPayloadBytes = out.NLiteralPayloadBytes + out.NLmdPayloadBytes

	// Freq tables
	srcCur := uint32(0)
	// TODO: why -32 ?
	srcEnd := getField(v2, 0, 32) - 32 // first byte after header
	var accum uint32
	var accumNbits int

	// No freq tables?
	if srcEnd == srcCur {
		return nil // OK, freq tables were omitted
	}

	for i := 0; i < (LZFSE_ENCODE_L_SYMBOLS + LZFSE_ENCODE_M_SYMBOLS +
		LZFSE_ENCODE_D_SYMBOLS + LZFSE_ENCODE_LITERAL_SYMBOLS); i++ {
		// Refill accum, one byte at a time, until we reach end of header, or accum is full
		for srcCur < srcEnd && accumNbits+8 <= 32 {
			accum |= uint32(in.Freq[srcCur]) << accumNbits
			accumNbits += 8
			srcCur++
		}

		// Decode and store value
		nbits := 0
		switch idx := i; {
		case idx < LZFSE_ENCODE_L_SYMBOLS_MAX:
			out.LFreq[idx] = decodeV1FreqValue(accum, &nbits)
		case LZFSE_ENCODE_L_SYMBOLS_MAX <= idx && idx < LZFSE_ENCODE_M_SYMBOLS_MAX:
			out.MFreq[idx-LZFSE_ENCODE_L_SYMBOLS_MAX] = decodeV1FreqValue(accum, &nbits)
		case LZFSE_ENCODE_M_SYMBOLS_MAX <= idx && idx < LZFSE_ENCODE_D_SYMBOLS_MAX:
			out.DFreq[idx-LZFSE_ENCODE_M_SYMBOLS_MAX] = decodeV1FreqValue(accum, &nbits)
		case LZFSE_ENCODE_D_SYMBOLS_MAX <= idx && idx < LZFSE_ENCODE_LITERAL_SYMBOLS_MAX:
			out.LiteralFreq[idx-LZFSE_ENCODE_D_SYMBOLS_MAX] = decodeV1FreqValue(accum, &nbits)
		}

		if nbits > accumNbits {
			return fmt.Errorf("decodeV1 failed")
		}

		// Consume nbits bits
		accum >>= nbits
		accumNbits -= nbits
	}

	if accumNbits >= 8 || srcCur != srcEnd {
		return fmt.Errorf("failed to end up exactly at the end of header, with less than 8 bits in accumulator")
	}

	return nil
}

func (s *Decoder) decodeLmdExecuteMatch(bs *lzfseCompressedBlockDecoderState) error {

	var litIdx int32

	//  Error if D is out of range, so that we avoid passing through
	//  uninitialized data or accesssing memory out of the destination
	//  buffer.
	if uint32(bs.DValue) > dst+bs.LValue {
		return fmt.Errorf("LZFSE_STATUS_ERROR")
	}

	if bs.LValue+bs.MValue <= remainingBytes {
		//  If we have plenty of space remaining, we can copy the literal
		//  and match with 16- and 32-byte operations, without worrying
		//  about writing off the end of the buffer.
		remainingBytes -= bs.LValue + bs.MValue
		copy(dst, lit, bs.LValue)
		dst += bs.LValue
		lit += bs.LValue
		//  For the match, we have two paths; a fast copy by 16-bytes if
		//  the match distance is large enough to allow it, and a more
		//  careful path that applies a permutation to account for the
		//  possible overlap between source and destination if the distance
		//  is small.
		if bs.DValue >= 8 || bs.DValue >= bs.MValue {
			copy(dst, dst-bs.DValue, bs.MValue)
		} else {
			for i := int32(0); i < bs.MValue; i++ {
				dst[i] = dst[i-bs.DValue]
			}
		}
		dst += bs.MValue
	} else {
		//  Otherwise, we are very close to the end of the destination
		//  buffer, so we cannot use wide copies that slop off the end
		//  of the region that we are copying to. First, we restore
		//  the true length remaining, rather than the sham value we've
		//  been using so far.
		// remainingBytes += 32
		//  Now, we process the literal. Either there's space for it
		//  or there isn't; if there is, we copy the whole thing and
		//  update all the pointers and lengths to reflect the copy.
		if bs.LValue <= remainingBytes {
			for i := int32(0); i < bs.LValue; i++ {
				dst[i] = lit[i]
			}
			dst += bs.LValue
			lit += bs.LValue
			remainingBytes -= bs.LValue
			bs.LValue = 0
		} else {
			//  There isn't enough space to fit the whole literal. Copy as
			//  much of it as we can, update the pointers and the value of
			//  L, and report that the destination buffer is full. Note that
			//  we always write right up to the end of the destination buffer.
			for i := 0; i < remainingBytes; i++ {
				dst[i] = lit[i]
			}
			dst += remainingBytes
			lit += remainingBytes
			bs.LValue -= remainingBytes
			// goto DestinationBufferIsFull;
			s.CompressedLzfseBlockState.LValue = bs.LValue
			s.CompressedLzfseBlockState.MValue = bs.MValue
			s.CompressedLzfseBlockState.DValue = bs.DValue
			s.CompressedLzfseBlockState.LState = bs.LState
			s.CompressedLzfseBlockState.MState = bs.MState
			s.CompressedLzfseBlockState.DState = bs.DState
			s.CompressedLzfseBlockState.LmdInStream = bs.LmdInStream
			s.CompressedLzfseBlockState.NMatches = bs.NMatches
			s.CompressedLzfseBlockState.LmdInBuf = bs.LmdInBuf
			// bs->lmd_in_buf = (uint32_t)(src - s->src);
			s.CompressedLzfseBlockState.CurrentLiteral = bs.CurrentLiteral
			// bs->current_literal = lit;
			// s.dst = dst
			// s->dst = dst;
			return fmt.Errorf("LZFSE_STATUS_DST_FULL")
		}
		//  The match goes just like the literal does. We copy as much as
		//  we can byte-by-byte, and if we reach the end of the buffer
		//  before finishing, we return to the caller indicating that
		//  the buffer is full.
		if bs.MValue <= remainingBytes {
			for i := int32(0); i < bs.MValue; i++ {
				dst[i] = dst[i-bs.DValue]
			}
			dst += bs.MValue
			remainingBytes -= bs.MValue
			bs.MValue = 0
			// (void)M; // no dead store warning
			//  We don't need to update M = 0, because there's no partial
			//  symbol to continue executing. Either we're at the end of
			//  the block, in which case we will never need to resume with
			//  this state, or we're going to decode another L, M, D set,
			//  which will overwrite M anyway.
			//
			// But we still set M = 0, to maintain the post-condition.
		} else {
			for i := 0; i < remainingBytes; i++ {
				dst[i] = dst[i-bs.DValue]
			}
			dst += remainingBytes
			bs.MValue -= remainingBytes
			// GOTO DestinationBufferIsFull:
			//  Because we want to be able to resume decoding where we've left
			//  off (even in the middle of a literal or match), we need to
			//  update all of the block state fields with the current values
			//  so that we can resume execution from this point once the
			//  caller has given us more space to write into.
			s.CompressedLzfseBlockState.LValue = bs.LValue
			s.CompressedLzfseBlockState.MValue = bs.MValue
			s.CompressedLzfseBlockState.DValue = bs.DValue
			s.CompressedLzfseBlockState.LState = bs.LState
			s.CompressedLzfseBlockState.MState = bs.MState
			s.CompressedLzfseBlockState.DState = bs.DState
			s.CompressedLzfseBlockState.LmdInStream = bs.LmdInStream
			s.CompressedLzfseBlockState.NMatches = bs.NMatches
			s.CompressedLzfseBlockState.LmdInBuf = bs.LmdInBuf
			// bs->lmd_in_buf = (uint32_t)(src - s->src);
			s.CompressedLzfseBlockState.CurrentLiteral = bs.CurrentLiteral
			// bs->current_literal = lit;
			// s.dst = dst
			// s->dst = dst;
			return fmt.Errorf("LZFSE_STATUS_DST_FULL")
		}
		//  Restore the "sham" decremented value of remainingBytes and
		//  continue to the next L, M, D triple. We'll just be back in
		//  the careful path again, but this only happens at the very end
		//  of the buffer, so a little minor inefficiency here is a good
		//  tradeoff for simpler code.
		// remainingBytes -= 32
	}

	return nil
}

func (s *Decoder) decodeLMD() error {

	r := io.NewSectionReader(s.src, 0, 1<<63-1)
	bs := s.CompressedLzfseBlockState

	if s.CompressedLzfseBlockState.LState >= LZFSE_ENCODE_L_STATES {
		return fmt.Errorf("failed s.CompressedLzfseBlockState.LState < LZFSE_ENCODE_L_STATES assertion")
	}
	if s.CompressedLzfseBlockState.MState >= LZFSE_ENCODE_M_STATES {
		return fmt.Errorf("failed s.CompressedLzfseBlockState.MState < LZFSE_ENCODE_M_STATES assertion")
	}
	if s.CompressedLzfseBlockState.DState >= LZFSE_ENCODE_D_STATES {
		return fmt.Errorf("failed s.CompressedLzfseBlockState.DState < LZFSE_ENCODE_D_STATES assertion")
	}

	//  Number of bytes remaining in the destination buffer, minus 32 to
	//  provide a margin of safety for using overlarge copies on the fast path.
	//  This is a signed quantity, and may go negative when we are close to the
	//  end of the buffer.  That's OK; we're careful about how we handle it
	//  in the slow-and-careful match execution path.

	// remainingBytes := int32(dst.Len() - 32)

	//  If L or M is non-zero, that means that we have already started decoding
	//  this block, and that we needed to interrupt decoding to get more space
	//  from the caller.  There's a pending L, M, D triplet that we weren't
	//  able to completely process.  Jump ahead to finish executing that symbol
	//  before decoding new values.
	if s.CompressedLzfseBlockState.LValue != 0 || s.CompressedLzfseBlockState.MValue != 0 {
		// goto ExecuteMatch
		s.decodeLmdExecuteMatch(&s.CompressedLzfseBlockState)
	}

	for s.CompressedLzfseBlockState.NMatches > 0 {
		//  Decode the next L, M, D symbol from the input stream.
		if err := fseInCheckedFlush2(&s.CompressedLzfseBlockState.LmdInStream, s.src); err != nil {
			return errors.Wrap(err, "LZFSE_STATUS_ERROR - fseInCheckedFlush")
		}

		s.CompressedLzfseBlockState.LValue = fseValueDecode(&s.CompressedLzfseBlockState.LState, s.CompressedLzfseBlockState.LDecoder[:], &s.CompressedLzfseBlockState.LmdInStream)
		if s.CompressedLzfseBlockState.LState >= LZFSE_ENCODE_L_STATES {
			return fmt.Errorf("failed s.CompressedLzfseBlockState.LState < LZFSE_ENCODE_L_STATES assertion")
		}

		// TODO
		// if (int32(s.CompressedLzfseBlockState.CurrentLiteral) + s.CompressedLzfseBlockState.LValue) >= (s.CompressedLzfseBlockState.Literals + (LZFSE_LITERALS_PER_BLOCK + 64)) {
		// 	return fmt.Errorf("LZFSE_STATUS_ERROR")
		// }

		s.CompressedLzfseBlockState.MValue = fseValueDecode(&s.CompressedLzfseBlockState.MState, s.CompressedLzfseBlockState.MDecoder[:], &s.CompressedLzfseBlockState.LmdInStream)
		if s.CompressedLzfseBlockState.MState >= LZFSE_ENCODE_M_STATES {
			return fmt.Errorf("failed s.CompressedLzfseBlockState.MState < LZFSE_ENCODE_M_STATES assertion")
		}

		newD := fseValueDecode(&s.CompressedLzfseBlockState.DState, s.CompressedLzfseBlockState.DDecoder[:], &s.CompressedLzfseBlockState.LmdInStream)
		if s.CompressedLzfseBlockState.DState >= LZFSE_ENCODE_D_STATES {
			return fmt.Errorf("failed s.CompressedLzfseBlockState.DState < LZFSE_ENCODE_D_STATES assertion")
		}

		if newD > 0 {
			s.CompressedLzfseBlockState.DValue = newD
		}

		s.CompressedLzfseBlockState.NMatches--

		// ExecuteMatch:
		s.decodeLmdExecuteMatch(&s.CompressedLzfseBlockState)
	}

	return nil
}

// Decode decodes an encoded lzfse buffer
func (s *Decoder) decode() error {

	r := io.NewSectionReader(s.src, 0, 1<<63-1)

	for {
		switch s.blockMagic {
		case LZFSE_NO_BLOCK_MAGIC:
			log.Debug("LZFSE_NO_BLOCK_MAGIC")
			if err := binary.Read(s.src, binary.LittleEndian, &s.blockMagic); err != nil {
				return err
			}
			s.src.Seek(int64(-binary.Size(s.blockMagic)), io.SeekCurrent)

			if s.blockMagic == LZFSE_ENDOFSTREAM_BLOCK_MAGIC {
				log.Debug("LZFSE_ENDOFSTREAM_BLOCK_MAGIC")
				return nil
			}
			if s.blockMagic == LZFSE_UNCOMPRESSED_BLOCK_MAGIC {
				log.Debug("LZFSE_UNCOMPRESSED_BLOCK_MAGIC")
				return fmt.Errorf("not implimented")
			}
			if s.blockMagic == LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC {
				log.Debug("LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC")
				return fmt.Errorf("not implimented")
			}
			if s.blockMagic == LZFSE_COMPRESSEDV1_BLOCK_MAGIC || s.blockMagic == LZFSE_COMPRESSEDV2_BLOCK_MAGIC {
				log.Debug("LZFSE_COMPRESSEDV1_BLOCK_MAGIC || LZFSE_COMPRESSEDV2_BLOCK_MAGIC")
				var header1 compressedBlockHeaderV1
				var header2 compressedBlockHeaderV2
				// Decode compressed headers
				if s.blockMagic == LZFSE_COMPRESSEDV2_BLOCK_MAGIC {
					log.Debug("LZFSE_COMPRESSEDV2_BLOCK_MAGIC")
					if err := binary.Read(r, binary.LittleEndian, &header2); err != nil {
						return err
					}

					if err := decodeV1(&header1, header2); err != nil {
						return err
					}
					// Skip header
					s.src.Seek(int64(decodeV2HeaderSize(header2)), io.SeekCurrent)
				} else {
					// This should happen
					log.Error("Not LZFSE_COMPRESSEDV2_BLOCK_MAGIC")
					if err := binary.Read(r, binary.LittleEndian, &header1); err != nil {
						return err
					}
					// Skip header
					s.src.Seek(int64(binary.Size(header1)), io.SeekCurrent)
				}

				// Setup state for compressed V1 block from header
				s.CompressedLzfseBlockState.NLmdPayloadBytes = header1.NLmdPayloadBytes
				s.CompressedLzfseBlockState.NMatches = header1.NMatches
				fseInitDecoderTable(
					LZFSE_ENCODE_LITERAL_STATES,
					LZFSE_ENCODE_LITERAL_SYMBOLS,
					header1.LiteralFreq,
					&s.CompressedLzfseBlockState.LiteralDecoder,
				)
				fseInitValueLOrMDecoderTable(
					LZFSE_ENCODE_L_STATES, LZFSE_ENCODE_L_SYMBOLS, header1.LFreq[:],
					lExtraBits[:], lBaseValue[:], &s.CompressedLzfseBlockState.LDecoder)
				fseInitValueLOrMDecoderTable(
					LZFSE_ENCODE_M_STATES, LZFSE_ENCODE_M_SYMBOLS, header1.MFreq[:],
					mExtraBits[:], mBaseValue[:], &s.CompressedLzfseBlockState.MDecoder)
				fseInitValueDDecoderTable(
					LZFSE_ENCODE_D_STATES, LZFSE_ENCODE_D_SYMBOLS, header1.DFreq[:],
					dExtraBits[:], dBaseValue[:], &s.CompressedLzfseBlockState.DDecoder)

				// Decode literals
				var in fseInStream

				offset, _ := s.src.Seek(int64(header1.NLiteralPayloadBytes), io.SeekCurrent) // skip literal payload
				r.Seek(offset, io.SeekStart)

				//   const uint8_t *buf = s->src; // read bits backwards from the end
				if err := fseInCheckedInit(&in, header1.LiteralBits, r); err != nil {
					return fmt.Errorf("LZFSE_STATUS_ERROR")
				}

				state0 := header1.LiteralState[0]
				state1 := header1.LiteralState[1]
				state2 := header1.LiteralState[2]
				state3 := header1.LiteralState[3]

				for i := uint32(0); i < header1.NLiterals; i += 4 { // n_literals is multiple of 4
					pos, _ := r.Seek(0, io.SeekCurrent)
					fmt.Println("pos1:", pos)
					if err := fseInCheckedFlush(&in, r); err != nil {
						return fmt.Errorf("LZFSE_STATUS_ERROR: [57, 64] bits")
					}
					pos, _ = r.Seek(0, io.SeekCurrent)
					fmt.Println("pos2:", pos)
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
				{
					var in fseInStream
					// read bits backwards from the end
					offset, _ = s.src.Seek(0, io.SeekCurrent)
					r.Seek(offset+int64(header1.NLmdPayloadBytes), io.SeekStart)
					// TODO: here the C passes in s.src as last arg (instead of buff_start)
					if err := fseInCheckedInit(&in, header1.LmdBits, r); err != nil {
						return fmt.Errorf("LZFSE_STATUS_ERROR - fseInCheckedInit: %v", err)
					}
					s.CompressedLzfseBlockState.LState = header1.LState
					s.CompressedLzfseBlockState.MState = header1.MState
					s.CompressedLzfseBlockState.DState = header1.DState
					bufOffset, _ := r.Seek(0, io.SeekCurrent)
					offset, _ = s.src.Seek(0, io.SeekCurrent)
					s.CompressedLzfseBlockState.LmdInBuf = uint32(bufOffset - offset)
					s.CompressedLzfseBlockState.LValue = 0
					s.CompressedLzfseBlockState.MValue = 0
					//  Initialize D to an illegal value so we can't erroneously use
					//  an uninitialized "previous" value.
					s.CompressedLzfseBlockState.DValue = -1
					s.CompressedLzfseBlockState.LmdInStream = in
				}

				break
			}
			// Here we have an invalid magic number
			return fmt.Errorf("LZFSE_STATUS_ERROR - invalid magic number")
		case LZFSE_UNCOMPRESSED_BLOCK_MAGIC:
			log.Debug("LZFSE_UNCOMPRESSED_BLOCK_MAGIC")
			return fmt.Errorf("not implimented")
			// break
		case LZFSE_COMPRESSEDV1_BLOCK_MAGIC:
			log.Debug("LZFSE_COMPRESSEDV1_BLOCK_MAGIC")
			fallthrough
		case LZFSE_COMPRESSEDV2_BLOCK_MAGIC:
			log.Debug("LZFSE_COMPRESSEDV2_BLOCK_MAGIC")
			// Require the entire LMD payload to be in SRC
			// if (s->src_end <= s->src ||
			// 	s.CompressedLzfseBlockState.n_lmd_payload_bytes > (size_t)(s->src_end - s->src)) {
			// 		return fmt.Errorf("LZFSE_STATUS_SRC_EMPTY")
			// 	}

			if err := s.decodeLMD(); err != nil {
				return err
			}

			s.blockMagic = LZFSE_NO_BLOCK_MAGIC
			s.src.Seek(int64(s.CompressedLzfseBlockState.NLmdPayloadBytes), io.SeekCurrent) // to next block
			break
		case LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC:
			log.Debug("LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC")
			return fmt.Errorf("not implimented")
			// Run LZVN decoder
			// lzvn_decode(&dstate)
			// break
		default:
			return fmt.Errorf("LZFSE_STATUS_ERROR: invalid magic")
		}
	}
}
