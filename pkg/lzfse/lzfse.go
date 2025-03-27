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
	r      *io.SectionReader
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
	// TODO: should the scratch be more?
	scratch := make([]byte, 2*binary.Size(compressedBlockHeaderV1{}))
	return &Decoder{
		src: bytes.NewReader(append(data, scratch...)),
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

	for i := range LZFSE_ENCODE_L_SYMBOLS + LZFSE_ENCODE_M_SYMBOLS +
		LZFSE_ENCODE_D_SYMBOLS + LZFSE_ENCODE_LITERAL_SYMBOLS {
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

func (s *Decoder) decodeLmdExecuteMatch(bs *lzfseCompressedBlockDecoderState, literals *bytes.Reader) error {

	lBuf := make([]byte, bs.LValue)
	if err := binary.Read(literals, binary.LittleEndian, lBuf); err != nil {
		return fmt.Errorf("failed to read %d bytes from literals; %v", bs.LValue, err)
	}
	if _, err := s.dst.Write(lBuf); err != nil {
		return fmt.Errorf("failed to write literal bytes to dst buffer 'copy(dst, lit, L)'; %v", err)
	}

	reader := bytes.NewReader(s.dst.Bytes())
	reader.Seek(int64(-bs.DValue), io.SeekEnd)

	mBuf := make([]byte, bs.MValue)
	if bs.DValue >= bs.MValue {
		if err := binary.Read(reader, binary.LittleEndian, mBuf); err != nil {
			return fmt.Errorf("failed to read %d bytes from 'dst[i - D]'; %v", bs.MValue, err)
		}
	} else {
		for i := int32(0); i < bs.MValue; i++ {
			if i < bs.DValue {
				b, err := reader.ReadByte()
				if err == io.EOF {
					break
				}
				if err != nil {
					return fmt.Errorf("failed to ReadByte 'dst[%d] = dst[%d - %d]' buffer; %v", i, i, bs.DValue, err)
				}
				mBuf[i] = b
			} else {
				mBuf[i] = mBuf[i-bs.DValue]
			}
		}
	}

	if _, err := s.dst.Write(mBuf); err != nil {
		return fmt.Errorf("failed to Write to dst buffer 'copy(dst, dst - D, M)'; %v", err)
	}

	return nil
}

func (s *Decoder) decodeLMD() error {

	s.r.Seek(int64(s.CompressedLzfseBlockState.LmdInBuf), io.SeekCurrent)
	literals := bytes.NewReader(s.CompressedLzfseBlockState.CurrentLiteral[:])

	if s.CompressedLzfseBlockState.LState >= LZFSE_ENCODE_L_STATES {
		return fmt.Errorf("failed LState < LZFSE_ENCODE_L_STATES assertion")
	}
	if s.CompressedLzfseBlockState.MState >= LZFSE_ENCODE_M_STATES {
		return fmt.Errorf("failed MState < LZFSE_ENCODE_M_STATES assertion")
	}
	if s.CompressedLzfseBlockState.DState >= LZFSE_ENCODE_D_STATES {
		return fmt.Errorf("failed DState < LZFSE_ENCODE_D_STATES assertion")
	}

	//  If L or M is non-zero, that means that we have already started decoding
	//  this block, and that we needed to interrupt decoding to get more space
	//  from the caller.  There's a pending L, M, D triplet that we weren't
	//  able to completely process.  Jump ahead to finish executing that symbol
	//  before decoding new values.
	if s.CompressedLzfseBlockState.LValue != 0 || s.CompressedLzfseBlockState.MValue != 0 {
		// goto ExecuteMatch
		err := s.decodeLmdExecuteMatch(&s.CompressedLzfseBlockState, literals)
		if err != nil {
			return errors.Wrap(err, "failed to ExecuteMatch")
		}
	}

	for s.CompressedLzfseBlockState.NMatches > 0 {
		//  Decode the next L, M, D symbol from the input stream.
		if err := fseInCheckedFlush(&s.CompressedLzfseBlockState.LmdInStream, s.r); err != nil {
			return errors.Wrap(err, "failed to fseInCheckedFlush")
		}

		// log.WithFields(log.Fields{
		// 	"Accum":      s.CompressedLzfseBlockState.LmdInStream.Accum,
		// 	"AccumNbits": s.CompressedLzfseBlockState.LmdInStream.AccumNbits,
		// }).Debug("LmdInStream")

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
		err := s.decodeLmdExecuteMatch(&s.CompressedLzfseBlockState, literals)
		if err != nil {
			return errors.Wrap(err, "failed to ExecuteMatch")
		}
	}
	return nil
}

func (s *Decoder) printOffsets() {
	srcOffset, _ := s.src.Seek(0, io.SeekCurrent)
	rOffset, _ := s.r.Seek(0, io.SeekCurrent)
	dstOffset := len(s.dst.Bytes())
	log.WithFields(log.Fields{
		"src": srcOffset,
		"r":   rOffset,
		"dst": dstOffset,
	}).Debug("Offsets")
}

func (s *Decoder) syncReaders() {
	offset, _ := s.src.Seek(0, io.SeekCurrent)
	s.r.Seek(offset, io.SeekStart)
}

// Decode decodes an encoded lzfse buffer
func (s *Decoder) decode() error {

	s.r = io.NewSectionReader(s.src, 0, 1<<63-1)

	for {
		switch s.blockMagic {
		case LZFSE_NO_BLOCK_MAGIC:
			if err := binary.Read(s.src, binary.LittleEndian, &s.blockMagic); err != nil {
				return fmt.Errorf("failed to read block magic: %v", err)
			}
			s.src.Seek(int64(-binary.Size(s.blockMagic)), io.SeekCurrent)
			s.syncReaders()
			if s.blockMagic == LZFSE_ENDOFSTREAM_BLOCK_MAGIC {
				// DONE
				return nil
			}
			if s.blockMagic == LZFSE_UNCOMPRESSED_BLOCK_MAGIC {
				return fmt.Errorf("found LZFSE_UNCOMPRESSED_BLOCK_MAGIC block - not implimented")
			}
			if s.blockMagic == LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC {
				return fmt.Errorf("found LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC block - not implimented")
			}
			if s.blockMagic == LZFSE_COMPRESSEDV1_BLOCK_MAGIC || s.blockMagic == LZFSE_COMPRESSEDV2_BLOCK_MAGIC {
				var header1 compressedBlockHeaderV1
				var header2 compressedBlockHeaderV2
				// Decode compressed headers
				if s.blockMagic == LZFSE_COMPRESSEDV2_BLOCK_MAGIC {
					// log.Debug("LZFSE_COMPRESSEDV2_BLOCK_MAGIC")
					if err := binary.Read(s.r, binary.LittleEndian, &header2); err != nil {
						return fmt.Errorf("failed to read LZFSE_COMPRESSEDV2_BLOCK_MAGIC header: %v", err)
					}

					if err := decodeV1(&header1, header2); err != nil {
						return fmt.Errorf("failed to LZFSE_COMPRESSEDV2_BLOCK_MAGIC decodeV1: %v", err)
					}
					// Skip header
					s.src.Seek(int64(decodeV2HeaderSize(header2)), io.SeekCurrent)
				} else {
					// This should NOT happen
					log.Error("Not LZFSE_COMPRESSEDV2_BLOCK_MAGIC - will possibly fail")
					if err := binary.Read(s.r, binary.LittleEndian, &header1); err != nil {
						return fmt.Errorf("failed to read LZFSE_COMPRESSEDV1_BLOCK_MAGIC header: %v", err)
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
				{
					var in fseInStream

					s.src.Seek(int64(header1.NLiteralPayloadBytes), io.SeekCurrent) // skip literal payload
					s.syncReaders()

					//   const uint8_t *buf = s->src; // read bits backwards from the end
					if err := fseInCheckedInit(&in, header1.LiteralBits, s.r); err != nil {
						return fmt.Errorf("failed to fseInCheckedInit; %v", err)
					}

					state0 := header1.LiteralState[0]
					state1 := header1.LiteralState[1]
					state2 := header1.LiteralState[2]
					state3 := header1.LiteralState[3]

					for i := uint32(0); i < header1.NLiterals; i += 4 { // n_literals is multiple of 4

						if err := fseInCheckedFlush(&in, s.r); err != nil {
							return fmt.Errorf("LZFSE_STATUS_ERROR: [57, 64] bits; %v", err)
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
				} // literals

				// SRC is not incremented to skip the LMD payload, since we need it
				// during block decode.
				// We will increment SRC at the end of the block only after this point.

				// Initialize the L,M,D decode stream, do not start decoding matches
				// yet, and store decoder state
				{
					var in fseInStream
					// read bits backwards from the end
					s.syncReaders()
					s.r.Seek(int64(header1.NLmdPayloadBytes), io.SeekCurrent)

					if err := fseInCheckedInit(&in, header1.LmdBits, s.r); err != nil {
						return fmt.Errorf("LZFSE_STATUS_ERROR - fseInCheckedInit: %v", err)
					}

					s.CompressedLzfseBlockState.LState = header1.LState
					s.CompressedLzfseBlockState.MState = header1.MState
					s.CompressedLzfseBlockState.DState = header1.DState
					bufOffset, _ := s.r.Seek(0, io.SeekCurrent)
					offset, _ := s.src.Seek(0, io.SeekCurrent)
					s.CompressedLzfseBlockState.LmdInBuf = uint32(bufOffset - offset)
					s.CompressedLzfseBlockState.LValue = 0
					s.CompressedLzfseBlockState.MValue = 0
					//  Initialize D to an illegal value so we can't erroneously use an uninitialized "previous" value.
					s.CompressedLzfseBlockState.DValue = -1
					s.CompressedLzfseBlockState.LmdInStream = in

					s.syncReaders()
				}

				break
			}
			// Here we have an invalid magic number
			return fmt.Errorf("LZFSE_STATUS_ERROR - invalid magic number")
		case LZFSE_UNCOMPRESSED_BLOCK_MAGIC:
			return fmt.Errorf("found LZFSE_UNCOMPRESSED_BLOCK_MAGIC block - not implimented")
			// break
		case LZFSE_COMPRESSEDV1_BLOCK_MAGIC:
			// log.Debug("LZFSE_COMPRESSEDV1_BLOCK_MAGIC")
			fallthrough
		case LZFSE_COMPRESSEDV2_BLOCK_MAGIC:
			// log.Debug("LZFSE_COMPRESSEDV2_BLOCK_MAGIC")
			// Require the entire LMD payload to be in SRC
			// if (s->src_end <= s->src ||
			// 	s.CompressedLzfseBlockState.n_lmd_payload_bytes > (size_t)(s->src_end - s->src)) {
			// 		return fmt.Errorf("LZFSE_STATUS_SRC_EMPTY")
			// 	}

			if err := s.decodeLMD(); err != nil {
				return fmt.Errorf("failed to LZFSE_COMPRESSED decodeLMD: %v", err)
			}

			s.blockMagic = LZFSE_NO_BLOCK_MAGIC
			s.src.Seek(int64(s.CompressedLzfseBlockState.NLmdPayloadBytes), io.SeekCurrent) // to next block
			s.syncReaders()
			break
		case LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC:
			return fmt.Errorf("found LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC block - not implimented")
			// Run LZVN decoder
			// lzvn_decode(&dstate)
			// break
		default:
			return fmt.Errorf("LZFSE_STATUS_ERROR: invalid magic")
		}
	}
}
