package lzfse

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"
)

// fseBitCount signed type used to represent bit count.
type fseBitCount int32

// fseState unsigned type used to represent FSE state.
type fseState uint16

// fseInStream object representing an input stream.
type fseInStream struct {
	Accum      uint64      // Input bits
	AccumNbits fseBitCount // Number of valid bits in ACCUM, other bits are 0
}

// fseDecoderEntry entry for one state in the decoder table (32b).
type fseDecoderEntry struct { // DO NOT REORDER THE FIELDS
	k      int8  // Number of bits to read
	symbol uint8 // Emitted symbol
	delta  int16 // Signed increment used to compute next state (+bias)
}

func (f fseDecoderEntry) ToInt32() int32 {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, f)
	return int32(binary.LittleEndian.Uint32(buf.Bytes()))
}

// fseValueDecoderEntry entry for one state in the value decoder table (64b).
type fseValueDecoderEntry struct {
	TotalBits uint8 // state bits + extra value bits = shift for next decode
	ValueBits uint8 // extra value bits
	Delta     int16 // state base (delta)
	Vbase     int32 // value base
}

func (f fseValueDecoderEntry) ToInt64() int64 {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, f)
	return int64(binary.LittleEndian.Uint64(buf.Bytes()))
}

func fseInitDecoderTable(nstates, nsymbols int, freq [256]uint16, t *[1024]int32) error {
	var sumOfFreq, lDecoderIdx int

	nClz := bits.LeadingZeros(uint(nstates))

	for i := range nsymbols {
		f := int(freq[i])
		if f == 0 {
			continue // skip this symbol, no occurrences
		}
		sumOfFreq += f

		if sumOfFreq > nstates {
			return fmt.Errorf("sumOfFreq > nstates")
		}

		k := bits.LeadingZeros(uint(f)) - nClz // shift needed to ensure N <= (F<<K) < 2*N
		j0 := ((2 * nstates) >> k) - f

		// Initialize all states S reached by this symbol: OFFSET <= S < OFFSET + F
		for j := range f {
			var e fseDecoderEntry

			e.symbol = uint8(i)
			if j < j0 {
				e.k = int8(k)
				e.delta = int16(((f + j) << k) - nstates)
			} else {
				e.k = int8(k - 1)
				e.delta = int16((j - j0) << (k - 1))
			}
			t[lDecoderIdx] = e.ToInt32()
			lDecoderIdx++
		}
	}

	return nil
}

func fseInitValueLOrMDecoderTable(nstates, nsymbols int, freq []uint16, symbolVbits []uint8,
	symbolVbase []int32, t *[64]fseValueDecoderEntry) {
	var dDecoderIdx int

	nClz := bits.LeadingZeros(uint(nstates))
	for i := range nsymbols {
		f := int(freq[i])

		if f == 0 {
			continue // skip this symbol, no occurrences
		}
		k := bits.LeadingZeros(uint(f)) - nClz // shift needed to ensure N <= (F<<K) < 2*N
		j0 := ((2 * nstates) >> k) - f

		var ei fseValueDecoderEntry
		ei.ValueBits = symbolVbits[i]
		ei.Vbase = symbolVbase[i]

		// Initialize all states S reached by this symbol: OFFSET <= S < OFFSET + F
		for j := range f {
			e := ei
			if j < j0 {
				e.TotalBits = uint8(k) + e.ValueBits
				e.Delta = int16(((f + j) << k) - nstates)
			} else {
				e.TotalBits = uint8(k-1) + e.ValueBits
				e.Delta = int16((j - j0) << (k - 1))
			}
			t[dDecoderIdx] = e
			dDecoderIdx++
		}
	}
}

func fseInitValueDDecoderTable(nstates, nsymbols int, freq []uint16, symbolVbits []uint8,
	symbolVbase []int32, t *[256]fseValueDecoderEntry) {
	var dDecoderIdx int

	nClz := bits.LeadingZeros(uint(nstates))
	for i := range nsymbols {
		f := int(freq[i])

		if f == 0 {
			continue // skip this symbol, no occurrences
		}
		k := bits.LeadingZeros(uint(f)) - nClz // shift needed to ensure N <= (F<<K) < 2*N
		j0 := ((2 * nstates) >> k) - f

		var ei fseValueDecoderEntry
		ei.ValueBits = symbolVbits[i]
		ei.Vbase = symbolVbase[i]

		// Initialize all states S reached by this symbol: OFFSET <= S < OFFSET + F
		for j := range f {
			e := ei
			if j < j0 {
				e.TotalBits = uint8(k) + e.ValueBits
				e.Delta = int16(((f + j) << k) - nstates)
			} else {
				e.TotalBits = uint8(k-1) + e.ValueBits
				e.Delta = int16((j - j0) << (k - 1))
			}
			t[dDecoderIdx] = e
			dDecoderIdx++
		}
	}
}

/* fseInCheckedInit initialize the fse input stream so that accum holds between 56
 *  and 63 bits. We never want to have 64 bits in the stream, because that allows
 *  us to avoid a special case in the fseInPull function (eliminating an
 *  unpredictable branch), while not requiring any additional fse_flush
 *  operations. This is why we have the special case for n == 0 (in which case
 *  we want to load only 7 bytes instead of 8). */
// func fseInCheckedInit(s *fseInStream, n fseBitCount, r *bytes.Reader, buffStart int64) error {
// func fseInCheckedInit(s *fseInStream, n fseBitCount, r *bytes.Reader) error {
func fseInCheckedInit(s *fseInStream, n fseBitCount, r *io.SectionReader) error {
	// pbuf := io.NewSectionReader(r, 0, 1<<63-1)
	if n != 0 {
		if _, err := r.Seek(-8, io.SeekCurrent); err != nil {
			return err
		}
		if err := binary.Read(r, binary.LittleEndian, &s.Accum); err != nil {
			return err
		}
		r.Seek(-8, io.SeekCurrent)
		s.AccumNbits = n + 64
	} else {
		r.Seek(-7, io.SeekCurrent)
		if err := binary.Read(r, binary.LittleEndian, &s.Accum); err != nil {
			return err
		}
		r.Seek(-8, io.SeekCurrent)
		s.Accum &= 0xffffffffffffff
		s.AccumNbits = n + 56
	}

	if (s.AccumNbits < 56 || s.AccumNbits >= 64) || ((s.Accum >> s.AccumNbits) != 0) {
		return fmt.Errorf("the incoming input is wrong (encoder should have zeroed the upper bits)")
	}

	return nil
}

/* fseInCheckedFlush - read in new bytes from buffer to ensure that we have a full
 * complement of bits in the stream object (again, between 56 and 63 bits).
 * checking the new value of *pbuf remains >= buf_start.
 * @return 0 if OK.
 * @return -1 on failure. */
// func fseInCheckedFlush(s *fseInStream, r *bytes.Reader) error {
func fseInCheckedFlush(s *fseInStream, r *io.SectionReader) error {
	//  Get number of bits to add to bring us into the desired range.
	nbits := (63 - s.AccumNbits) & -8
	//  Convert bits to bytes and decrement buffer address, then load new data.
	_, err := r.Seek(int64(-(nbits >> 3)), io.SeekCurrent)
	if err != nil {
		return err
	}
	var incoming uint64
	if err := binary.Read(r, binary.LittleEndian, &incoming); err != nil {
		return err
	}
	r.Seek(-8, io.SeekCurrent)
	// Update the state object and verify its validity (in DEBUG).
	s.Accum = (s.Accum << nbits) | fseMaskLsb64(incoming, nbits)
	s.AccumNbits += nbits
	if s.AccumNbits < 56 || s.AccumNbits >= 64 {
		return fmt.Errorf("failed to fseInCheckedFlush - s.AccumNbits < 56 || s.AccumNbits >= 64")
	}
	if (s.Accum >> s.AccumNbits) != 0 {
		return fmt.Errorf("failed to fseInCheckedFlush - (s.Accum >> s.AccumNbits) == 0")
	}
	return nil // OK
}

/* fseDecode - decode and return symbol using the decoder table, and update *pstate, in.
 *  @note The caller must ensure we have enough bits available in the input
 *  stream accumulator. */
func fseDecode(pstate *uint16, decoderTable [1024]int32, in *fseInStream) uint8 {
	e := decoderTable[*pstate]
	// Update state from K bits of input + DELTA
	*pstate = uint16(e>>16) + uint16(fseInPull(in, fseBitCount(e&0xff)))
	// Return the symbol for this state
	return uint8(fseExtractBits(uint64(e), 8, 8)) // symbol
}

/* fseValueDecode - decode and return value using the decoder table, and update *pstate, in value_decoder_table[nstates]
 * @note The caller must ensure we have enough bits available in the input
 * stream accumulator. */
func fseValueDecode(pstate *uint16, valueDecoderTable []fseValueDecoderEntry, in *fseInStream) int32 {
	entry := valueDecoderTable[*pstate]
	stateAndValueBits := uint32(fseInPull(in, fseBitCount(entry.TotalBits)))
	*pstate = uint16(entry.Delta) + uint16(stateAndValueBits>>entry.ValueBits)
	return entry.Vbase + int32(fseMaskLsb64(uint64(stateAndValueBits), fseBitCount(entry.ValueBits)))
}

// fseInPull - pull n bits out of the fse stream object.
func fseInPull(s *fseInStream, n fseBitCount) uint64 {
	//   assert(n >= 0 && n <= s.AccumNbits);
	s.AccumNbits -= n
	result := s.Accum >> s.AccumNbits
	s.Accum = fseMaskLsb64(s.Accum, s.AccumNbits)
	return result
}

// Mask the NBITS lsb of X. 0 <= NBITS < 64
func fseMaskLsb64(x uint64, nbits fseBitCount) uint64 {
	mtable := [65]uint64{
		0x0000000000000000, 0x0000000000000001, 0x0000000000000003,
		0x0000000000000007, 0x000000000000000f, 0x000000000000001f,
		0x000000000000003f, 0x000000000000007f, 0x00000000000000ff,
		0x00000000000001ff, 0x00000000000003ff, 0x00000000000007ff,
		0x0000000000000fff, 0x0000000000001fff, 0x0000000000003fff,
		0x0000000000007fff, 0x000000000000ffff, 0x000000000001ffff,
		0x000000000003ffff, 0x000000000007ffff, 0x00000000000fffff,
		0x00000000001fffff, 0x00000000003fffff, 0x00000000007fffff,
		0x0000000000ffffff, 0x0000000001ffffff, 0x0000000003ffffff,
		0x0000000007ffffff, 0x000000000fffffff, 0x000000001fffffff,
		0x000000003fffffff, 0x000000007fffffff, 0x00000000ffffffff,
		0x00000001ffffffff, 0x00000003ffffffff, 0x00000007ffffffff,
		0x0000000fffffffff, 0x0000001fffffffff, 0x0000003fffffffff,
		0x0000007fffffffff, 0x000000ffffffffff, 0x000001ffffffffff,
		0x000003ffffffffff, 0x000007ffffffffff, 0x00000fffffffffff,
		0x00001fffffffffff, 0x00003fffffffffff, 0x00007fffffffffff,
		0x0000ffffffffffff, 0x0001ffffffffffff, 0x0003ffffffffffff,
		0x0007ffffffffffff, 0x000fffffffffffff, 0x001fffffffffffff,
		0x003fffffffffffff, 0x007fffffffffffff, 0x00ffffffffffffff,
		0x01ffffffffffffff, 0x03ffffffffffffff, 0x07ffffffffffffff,
		0x0fffffffffffffff, 0x1fffffffffffffff, 0x3fffffffffffffff,
		0x7fffffffffffffff, 0xffffffffffffffff,
	}
	return x & mtable[nbits]
}

// fseExtractBits - select nbits at index start from x.
// 0 <= start <= start+nbits <= 64
func fseExtractBits(x uint64, start, nbits fseBitCount) uint64 {
	return fseMaskLsb64(x>>start, nbits)
}
