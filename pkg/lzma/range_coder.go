// Copyright (c) 2010, Andrei Vieru. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package lzma

import (
	"bufio"
	"io"
)

const (
	kTopValue             = 1 << 24
	kNumBitModelTotalBits = 11
	kBitModelTotal        = 1 << kNumBitModelTotalBits
	kNumMoveBits          = 5
)

// The actual read interface needed by NewDecoder. If the passed in io.Reader
// does not also have ReadByte, the NewDecoder will introduce its own buffering.
//
type Reader interface {
	io.Reader
	ReadByte() (c byte, err error)
}

type rangeDecoder struct {
	r      Reader
	rrange uint32
	code   uint32
}

func makeReader(r io.Reader) Reader {
	if rr, ok := r.(Reader); ok {
		return rr
	}
	return bufio.NewReader(r)
}

func newRangeDecoder(r io.Reader) *rangeDecoder {
	rd := &rangeDecoder{
		r:      makeReader(r),
		rrange: 0xFFFFFFFF,
		code:   0,
	}
	buf := make([]byte, 5)
	_, err := io.ReadFull(rd.r, buf)
	if err != nil {
		throw(err)
	}
	for i := 0; i < len(buf); i++ {
		rd.code = rd.code<<8 | uint32(buf[i])
	}
	return rd
}

func (rd *rangeDecoder) decodeDirectBits(numTotalBits uint32) (res uint32) {
	for i := numTotalBits; i != 0; i-- {
		rd.rrange >>= 1
		t := (rd.code - rd.rrange) >> 31
		rd.code -= rd.rrange & (t - 1)
		res = res<<1 | (1 - t)
		if rd.rrange < kTopValue {
			c, err := rd.r.ReadByte()
			if err != nil {
				throw(err)
			}
			rd.code = rd.code<<8 | uint32(c)
			rd.rrange <<= 8
		}
	}
	return
}

func (rd *rangeDecoder) decodeBit(probs []uint16, index uint32) (res uint32) {
	prob := probs[index]
	newBound := (rd.rrange >> kNumBitModelTotalBits) * uint32(prob)
	if rd.code < newBound {
		rd.rrange = newBound
		probs[index] = prob + (kBitModelTotal-prob)>>kNumMoveBits
		if rd.rrange < kTopValue {
			b, err := rd.r.ReadByte()
			if err != nil {
				throw(err)
			}
			rd.code = rd.code<<8 | uint32(b)
			rd.rrange <<= 8
		}
		res = 0
	} else {
		rd.rrange -= newBound
		rd.code -= newBound
		probs[index] = prob - prob>>kNumMoveBits
		if rd.rrange < kTopValue {
			b, err := rd.r.ReadByte()
			if err != nil {
				throw(err)
			}
			rd.code = rd.code<<8 | uint32(b)
			rd.rrange <<= 8
		}
		res = 1
	}
	return
}

func initBitModels(length uint32) (probs []uint16) {
	probs = make([]uint16, length)
	val := uint16(kBitModelTotal) >> 1
	for i := uint32(0); i < length; i++ {
		probs[i] = val // 1 << 10
	}
	return
}

const (
	kNumMoveReducingBits  = 2
	kNumBitPriceShiftBits = 6
)

// The actual write interface needed by NewEncoder. If the passed in io.Writer
// does not also have WriteByte and Flush, the NewEncoder will wrap it into an
// bufio.Writer.
//
type Writer interface {
	io.Writer
	Flush() error
	WriteByte(c byte) error
}

type rangeEncoder struct {
	w         Writer
	low       uint64
	pos       uint64
	cacheSize uint32
	cache     uint32
	rrange    uint32
}

func makeWriter(w io.Writer) Writer {
	if ww, ok := w.(Writer); ok {
		return ww
	}
	return bufio.NewWriter(w)
}

func newRangeEncoder(w io.Writer) *rangeEncoder {
	return &rangeEncoder{
		w:         makeWriter(w),
		low:       0,
		pos:       0,
		cacheSize: 1,
		cache:     0,
		rrange:    0xFFFFFFFF,
	}
}

func (re *rangeEncoder) flush() {
	for i := 0; i < 5; i++ {
		re.shiftLow()
	}
	err := re.w.Flush()
	if err != nil {
		throw(err)
	}
}

func (re *rangeEncoder) shiftLow() {
	lowHi := uint32(re.low >> 32)
	if lowHi != 0 || re.low < uint64(0x00000000FF000000) {
		re.pos += uint64(re.cacheSize)
		temp := re.cache
		dwtemp := uint32(1) // execute the loop at least once (do-while)
		for ; dwtemp != 0; dwtemp = re.cacheSize {
			err := re.w.WriteByte(byte(temp + lowHi))
			if err != nil {
				throw(err)
			}
			temp = 0x000000FF
			re.cacheSize--
		}
		re.cache = uint32(re.low) >> 24
	}
	re.cacheSize++
	re.low = uint64(uint32(re.low) << 8)
}

func (re *rangeEncoder) encodeDirectBits(v, numTotalBits uint32) {
	for i := numTotalBits - 1; int32(i) >= 0; i-- {
		re.rrange >>= 1
		if (v>>i)&1 == 1 {
			re.low += uint64(re.rrange)
		}
		if re.rrange < kTopValue {
			re.rrange <<= 8
			re.shiftLow()
		}
	}
}

func (re *rangeEncoder) processedSize() uint64 {
	return uint64(re.cacheSize) + re.pos + 4
}

func (re *rangeEncoder) encode(probs []uint16, index, symbol uint32) {
	prob := probs[index]
	newBound := (re.rrange >> kNumBitModelTotalBits) * uint32(prob)
	if symbol == 0 {
		re.rrange = newBound
		probs[index] = prob + (kBitModelTotal-prob)>>kNumMoveBits
	} else {
		re.low += uint64(newBound) & uint64(0xFFFFFFFFFFFFFFFF)
		re.rrange -= newBound
		probs[index] = prob - prob>>kNumMoveBits
	}
	if re.rrange < kTopValue {
		re.rrange <<= 8
		re.shiftLow()
	}
}

var probPrices []uint32 = make([]uint32, kBitModelTotal>>kNumMoveReducingBits) // len(probPrices) = 512

// should be called in the encoder's contructor.
func initProbPrices() {
	kNumBits := uint32(kNumBitModelTotalBits - kNumMoveReducingBits)
	for i := kNumBits - 1; int32(i) >= 0; i-- {
		start := uint32(1) << (kNumBits - i - 1)
		end := uint32(1) << (kNumBits - i)
		for j := start; j < end; j++ {
			probPrices[j] = i<<kNumBitPriceShiftBits + ((end-j)<<kNumBitPriceShiftBits)>>(kNumBits-i-1)
		}
	}
}

func getPrice(prob uint16, symbol uint32) uint32 {
	return probPrices[(((uint32(prob)-symbol)^(-symbol))&(uint32(kBitModelTotal)-1))>>kNumMoveReducingBits]
}

func getPrice0(prob uint16) uint32 {
	return probPrices[prob>>kNumMoveReducingBits]
}

func getPrice1(prob uint16) uint32 {
	return probPrices[(kBitModelTotal-prob)>>kNumMoveReducingBits]
}
