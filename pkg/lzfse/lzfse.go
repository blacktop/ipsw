package lzfse

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/apex/log"
)

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

// Decode decodes an encoded lzfse buffer
func Decode(data []byte) ([]byte, error) {

	var blockMagic uint32
	var out []byte

	r := bytes.NewReader(data)

	// Decode
	for {
		switch blockMagic {
		case LZFSE_NO_BLOCK_MAGIC:
			log.Debug("LZFSE_NO_BLOCK_MAGIC")
			if err := binary.Read(r, binary.LittleEndian, &blockMagic); err != nil {
				return nil, err
			}
			r.Seek(int64(-binary.Size(blockMagic)), io.SeekCurrent)

			if blockMagic == LZFSE_ENDOFSTREAM_BLOCK_MAGIC {
				log.Debug("LZFSE_ENDOFSTREAM_BLOCK_MAGIC")
				return out, nil
			}
			if blockMagic == LZFSE_UNCOMPRESSED_BLOCK_MAGIC {
				log.Debug("LZFSE_UNCOMPRESSED_BLOCK_MAGIC")
				return nil, fmt.Errorf("not implimented")
			}
			if blockMagic == LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC {
				log.Debug("LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC")
				return nil, fmt.Errorf("not implimented")
			}
			// TODO: this is used <===========================
			if blockMagic == LZFSE_COMPRESSEDV1_BLOCK_MAGIC ||
				blockMagic == LZFSE_COMPRESSEDV2_BLOCK_MAGIC {
				log.Debug("LZFSE_COMPRESSEDV1_BLOCK_MAGIC || LZFSE_COMPRESSEDV2_BLOCK_MAGIC")
				var header1 compressedBlockHeaderV1
				var header2 compressedBlockHeaderV2
				// Decode compressed headers
				if blockMagic == LZFSE_COMPRESSEDV2_BLOCK_MAGIC {
					log.Debug("LZFSE_COMPRESSEDV2_BLOCK_MAGIC")
					if err := binary.Read(r, binary.LittleEndian, &header2); err != nil {
						return nil, err
					}
					err := decodeV1(&header1, header2)
					if err != nil {
						return nil, err
					}
				} else {
					// This should happen
					log.Error("Not LZFSE_COMPRESSEDV2_BLOCK_MAGIC")
					if err := binary.Read(r, binary.LittleEndian, &header1); err != nil {
						return nil, err
					}
				}
				r.Seek(int64(binary.Size(compressedBlockHeaderV1{})), io.SeekCurrent)

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
