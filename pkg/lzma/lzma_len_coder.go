// Copyright (c) 2010, Andrei Vieru. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package lzma

type lenCoder struct {
	choice    []uint16
	lowCoder  []*rangeBitTreeCoder
	midCoder  []*rangeBitTreeCoder
	highCoder *rangeBitTreeCoder
}

func newLenCoder(numPosStates /*1 << pb*/ uint32) *lenCoder {
	lc := &lenCoder{
		choice:    initBitModels(2),
		lowCoder:  make([]*rangeBitTreeCoder, kNumPosStatesMax),
		midCoder:  make([]*rangeBitTreeCoder, kNumPosStatesMax),
		highCoder: newRangeBitTreeCoder(kNumHighLenBits),
	}
	for i := uint32(0); i < numPosStates; i++ {
		lc.lowCoder[i] = newRangeBitTreeCoder(kNumLowLenBits)
		lc.midCoder[i] = newRangeBitTreeCoder(kNumMidLenBits)
	}
	return lc
}

func (lc *lenCoder) decode(rd *rangeDecoder, posState uint32) (res uint32) {
	i := rd.decodeBit(lc.choice, 0)
	if i == 0 {
		res = lc.lowCoder[posState].decode(rd)
		return
	}
	res = kNumLowLenSymbols
	j := rd.decodeBit(lc.choice, 1)
	if j == 0 {
		k := lc.midCoder[posState].decode(rd)
		res += k
		return
	} else {
		l := lc.highCoder.decode(rd)
		res = res + kNumMidLenSymbols + l
		return
	}
	return
}

func (lc *lenCoder) encode(re *rangeEncoder, symbol, posState uint32) {
	if symbol < kNumLowLenSymbols {
		re.encode(lc.choice, 0, 0)
		lc.lowCoder[posState].encode(re, symbol)
	} else {
		symbol -= kNumLowLenSymbols
		re.encode(lc.choice, 0, 1)
		if symbol < kNumMidLenSymbols {
			re.encode(lc.choice, 1, 0)
			lc.midCoder[posState].encode(re, symbol)
		} else {
			re.encode(lc.choice, 1, 1)
			lc.highCoder.encode(re, symbol-kNumMidLenSymbols)
		}
	}
}

// write prices into prices []uint32
func (lc *lenCoder) setPrices(prices []uint32, posState, numSymbols, st uint32) {
	a0 := getPrice0(lc.choice[0])
	a1 := getPrice1(lc.choice[0])
	b0 := a1 + getPrice0(lc.choice[1])
	b1 := a1 + getPrice1(lc.choice[1])

	var i uint32
	for i = 0; i < kNumLowLenSymbols; i++ {
		if i >= numSymbols {
			return
		}
		prices[st+i] = a0 + lc.lowCoder[posState].getPrice(i)
	}
	for ; i < kNumLowLenSymbols+kNumMidLenSymbols; i++ {
		if i >= numSymbols {
			return
		}
		prices[st+i] = b0 + lc.midCoder[posState].getPrice(i-kNumLowLenSymbols)
	}
	for ; i < numSymbols; i++ {
		prices[st+i] = b1 + lc.highCoder.getPrice(i-kNumLowLenSymbols-kNumMidLenSymbols)
	}
}


type lenPriceTableCoder struct {
	lc        *lenCoder
	prices    []uint32
	counters  []uint32
	tableSize uint32
}

func newLenPriceTableCoder(tableSize, numPosStates uint32) *lenPriceTableCoder {
	pc := &lenPriceTableCoder{
		lc:        newLenCoder(numPosStates),
		prices:    make([]uint32, kNumLenSymbols<<kNumPosStatesBitsMax),
		counters:  make([]uint32, kNumPosStatesMax),
		tableSize: tableSize,
	}
	for posState := uint32(0); posState < numPosStates; posState++ {
		pc.updateTable(posState)
	}
	return pc
}

func (pc *lenPriceTableCoder) updateTable(posState uint32) {
	pc.lc.setPrices(pc.prices, posState, pc.tableSize, posState*kNumLenSymbols)
	pc.counters[posState] = pc.tableSize
}

func (pc *lenPriceTableCoder) getPrice(symbol, posState uint32) uint32 {
	return pc.prices[posState*kNumLenSymbols+symbol]
}

func (pc *lenPriceTableCoder) encode(re *rangeEncoder, symbol, posState uint32) {
	pc.lc.encode(re, symbol, posState)
	pc.counters[posState]--
	if pc.counters[posState] == 0 {
		pc.updateTable(posState)
	}
}
