// Copyright (c) 2010, Andrei Vieru. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package lzma

type rangeBitTreeCoder struct {
	models       []uint16 // length(models) is at most 1<<8
	numBitLevels uint32   // min 2; max 8
}

func newRangeBitTreeCoder(numBitLevels uint32) *rangeBitTreeCoder {
	return &rangeBitTreeCoder{
		numBitLevels: numBitLevels,
		models:       initBitModels(1 << numBitLevels),
	}
}

func (rc *rangeBitTreeCoder) decode(rd *rangeDecoder) (res uint32) {
	res = 1
	for bitIndex := rc.numBitLevels; bitIndex != 0; bitIndex-- {
		bit := rd.decodeBit(rc.models, res)
		res = res<<1 + bit
	}
	res -= 1 << rc.numBitLevels
	return
}

func (rc *rangeBitTreeCoder) reverseDecode(rd *rangeDecoder) (res uint32) {
	index := uint32(1)
	res = 0
	for bitIndex := uint32(0); bitIndex < rc.numBitLevels; bitIndex++ {
		bit := rd.decodeBit(rc.models, index)
		index <<= 1
		index += bit
		res |= bit << bitIndex
	}
	return
}

func reverseDecodeIndex(rd *rangeDecoder, models []uint16, startIndex, numBitModels uint32) (res uint32) {
	index := uint32(1)
	res = 0
	for bitIndex := uint32(0); bitIndex < numBitModels; bitIndex++ {
		bit := rd.decodeBit(models, startIndex+index)
		index <<= 1
		index += bit
		res |= bit << bitIndex
	}
	return
}

func (rc *rangeBitTreeCoder) encode(re *rangeEncoder, symbol uint32) {
	m := uint32(1)
	for bitIndex := rc.numBitLevels; bitIndex != 0; {
		bitIndex--
		bit := (symbol >> bitIndex) & 1
		re.encode(rc.models, m, bit)
		m = m<<1 | bit
	}
}

func (rc *rangeBitTreeCoder) reverseEncode(re *rangeEncoder, symbol uint32) {
	m := uint32(1)
	for i := uint32(0); i < rc.numBitLevels; i++ {
		bit := symbol & 1
		re.encode(rc.models, m, bit)
		m = m<<1 | bit
		symbol >>= 1
	}
}

func (rc *rangeBitTreeCoder) getPrice(symbol uint32) (res uint32) {
	res = 0
	m := uint32(1)
	for bitIndex := rc.numBitLevels; bitIndex != 0; {
		bitIndex--
		bit := (symbol >> bitIndex) & 1
		res += getPrice(rc.models[m], bit)
		m = m<<1 + bit
	}
	return
}

func (rc *rangeBitTreeCoder) reverseGetPrice(symbol uint32) (res uint32) {
	res = 0
	m := uint32(1)
	for i := rc.numBitLevels; i != 0; i-- {
		bit := symbol & 1
		symbol >>= 1
		res += getPrice(rc.models[m], bit)
		m = m<<1 | bit
	}
	return
}

func reverseGetPriceIndex(models []uint16, startIndex, numBitLevels, symbol uint32) (res uint32) {
	res = 0
	m := uint32(1)
	for i := numBitLevels; i != 0; i-- {
		bit := symbol & 1
		symbol >>= 1
		res += getPrice(models[startIndex+m], bit)
		m = m<<1 | bit
	}
	return
}

func reverseEncodeIndex(re *rangeEncoder, models []uint16, startIndex, numBitLevels, symbol uint32) {
	m := uint32(1)
	for i := uint32(0); i < numBitLevels; i++ {
		bit := symbol & 1
		re.encode(models, startIndex+m, bit)
		m = m<<1 | bit
		symbol >>= 1
	}
}
