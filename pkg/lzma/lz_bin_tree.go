// Copyright (c) 2010, Andrei Vieru. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package lzma

import "io"

const (
	kHash2Size          = 1 << 10
	kHash3Size          = 1 << 16
	kBT2HashSize        = 1 << 16
	kStartMaxLen        = 1
	kHash3Offset        = kHash2Size
	kEmptyHashValue     = 0
	kMaxValForNormalize = (1 << 30) - 1
)

type lzBinTree struct {
	iw                   *lzInWindow
	son                  []uint32
	hash                 []uint32
	cyclicBufPos         uint32
	cyclicBufSize        uint32
	matchMaxLen          uint32
	cutValue             uint32
	hashMask             uint32
	hashSizeSum          uint32
	kvNumHashDirectBytes uint32
	kvMinMatchCheck      uint32
	kvFixHashSize        uint32
	hashArray            bool
}

func newLzBinTree(r io.Reader, historySize, keepAddBufBefore, matchMaxLen, keepAddBufAfter, numHashBytes uint32) *lzBinTree {
	bt := &lzBinTree{
		son:           make([]uint32, (historySize+1)*2), // history size is the dictSize from the encoder
		cyclicBufPos:  0,
		cyclicBufSize: historySize + 1,
		matchMaxLen:   matchMaxLen,
		cutValue:      16 + (matchMaxLen >> 1),
	}

	winSizeReserv := (historySize+keepAddBufBefore+matchMaxLen+keepAddBufAfter)/2 + 256
	bt.iw = newLzInWindow(r, historySize+keepAddBufBefore, matchMaxLen+keepAddBufAfter, winSizeReserv)

	if numHashBytes > 2 {
		bt.hashArray = true
		bt.kvNumHashDirectBytes = 0
		bt.kvMinMatchCheck = 4
		bt.kvFixHashSize = kHash2Size + kHash3Size
	} else {
		bt.hashArray = false
		bt.kvNumHashDirectBytes = 2
		bt.kvMinMatchCheck = 3
		bt.kvFixHashSize = 0
	}

	hs := uint32(kBT2HashSize)
	if bt.hashArray == true {
		hs = historySize - 1
		hs |= hs >> 1
		hs |= hs >> 2
		hs |= hs >> 4
		hs |= hs >> 8
		hs >>= 1
		hs |= 0xFFFF
		if hs > 1<<24 {
			hs >>= 1
		}
		bt.hashMask = hs
		hs++
		hs += bt.kvFixHashSize
	}
	bt.hashSizeSum = hs
	bt.hash = make([]uint32, bt.hashSizeSum)
	for i := uint32(0); i < bt.hashSizeSum; i++ {
		bt.hash[i] = kEmptyHashValue
	}

	bt.iw.reduceOffsets(0xFFFFFFFF)
	return bt
}

func normalizeLinks(items []uint32, numItems, subValue uint32) {
	for i := uint32(0); i < numItems; i++ {
		value := items[i]
		if value <= subValue {
			value = kEmptyHashValue
		} else {
			value -= subValue
		}
		items[i] = value
	}
}

func (bt *lzBinTree) normalize() {
	subValue := bt.iw.pos - bt.cyclicBufSize
	normalizeLinks(bt.son, bt.cyclicBufSize*2, subValue)
	normalizeLinks(bt.hash, bt.hashSizeSum, subValue)
	bt.iw.reduceOffsets(subValue)
}

func (bt *lzBinTree) movePos() {
	bt.cyclicBufPos++
	if bt.cyclicBufPos >= bt.cyclicBufSize {
		bt.cyclicBufPos = 0
	}
	bt.iw.movePos()
	if bt.iw.pos == kMaxValForNormalize {
		bt.normalize()
	}
}

func (bt *lzBinTree) getMatches(distances []uint32) uint32 {
	var lenLimit uint32
	if bt.iw.pos+bt.matchMaxLen <= bt.iw.streamPos {
		lenLimit = bt.matchMaxLen
	} else {
		lenLimit = bt.iw.streamPos - bt.iw.pos
		if lenLimit < bt.kvMinMatchCheck {
			bt.movePos()
			return 0
		}
	}

	offset := uint32(0)
	matchMinPos := uint32(0)
	if bt.iw.pos > bt.cyclicBufSize {
		matchMinPos = bt.iw.pos - bt.cyclicBufSize
	}
	cur := bt.iw.bufOffset + bt.iw.pos
	maxLen := uint32(kStartMaxLen)
	var hashValue uint32
	hash2Value := uint32(0)
	hash3Value := uint32(0)

	if bt.hashArray == true {
		tmp := crcTable[bt.iw.buf[cur]] ^ uint32(bt.iw.buf[cur+1])
		hash2Value = tmp & (kHash2Size - 1)
		tmp ^= uint32(bt.iw.buf[cur+2]) << 8
		hash3Value = tmp & (kHash3Size - 1)
		hashValue = (tmp ^ crcTable[bt.iw.buf[cur+3]]<<5) & bt.hashMask
	} else {
		hashValue = uint32(bt.iw.buf[cur]) ^ uint32(bt.iw.buf[cur+1])<<8
	}

	curMatch := bt.hash[bt.kvFixHashSize+hashValue]
	if bt.hashArray == true {
		curMatch2 := bt.hash[hash2Value]
		curMatch3 := bt.hash[kHash3Offset+hash3Value]
		bt.hash[hash2Value] = bt.iw.pos
		bt.hash[kHash3Offset+hash3Value] = bt.iw.pos
		if curMatch2 > matchMinPos {
			if bt.iw.buf[bt.iw.bufOffset+curMatch2] == bt.iw.buf[cur] {
				maxLen = 2
				distances[offset] = maxLen
				offset++
				distances[offset] = bt.iw.pos - curMatch2 - 1
				offset++
			}
		}
		if curMatch3 > matchMinPos {
			if bt.iw.buf[bt.iw.bufOffset+curMatch3] == bt.iw.buf[cur] {
				if curMatch3 == curMatch2 {
					offset -= 2
				}
				maxLen = 3
				distances[offset] = maxLen
				offset++
				distances[offset] = bt.iw.pos - curMatch3 - 1
				offset++
				curMatch2 = curMatch3
			}
		}
		if offset != 0 && curMatch2 == curMatch {
			offset -= 2
			maxLen = kStartMaxLen
		}
	}

	bt.hash[bt.kvFixHashSize+hashValue] = bt.iw.pos

	if bt.kvNumHashDirectBytes != 0 {
		if curMatch > matchMinPos {
			if bt.iw.buf[bt.iw.bufOffset+curMatch+bt.kvNumHashDirectBytes] != bt.iw.buf[cur+bt.kvNumHashDirectBytes] {
				maxLen = bt.kvNumHashDirectBytes
				distances[offset] = maxLen
				offset++
				distances[offset] = bt.iw.pos - curMatch - 1
				offset++
			}
		}
	}

	ptr0 := bt.cyclicBufPos<<1 + 1
	ptr1 := bt.cyclicBufPos << 1
	len0 := bt.kvNumHashDirectBytes
	len1 := bt.kvNumHashDirectBytes
	count := bt.cutValue

	for {
		if curMatch <= matchMinPos || count == 0 {
			bt.son[ptr1] = kEmptyHashValue
			bt.son[ptr0] = kEmptyHashValue
			break
		}
		count--

		delta := bt.iw.pos - curMatch
		var cyclicPos uint32
		if delta <= bt.cyclicBufPos {
			cyclicPos = (bt.cyclicBufPos - delta) << 1
		} else {
			cyclicPos = (bt.cyclicBufPos - delta + bt.cyclicBufSize) << 1
		}
		pby1 := bt.iw.bufOffset + curMatch
		length := minUInt32(len0, len1)
		if bt.iw.buf[pby1+length] == bt.iw.buf[cur+length] {
			for length++; length != lenLimit; length++ {
				if bt.iw.buf[pby1+length] != bt.iw.buf[cur+length] {
					break
				}
			}
			if maxLen < length {
				maxLen = length
				distances[offset] = maxLen
				offset++
				distances[offset] = delta - 1
				offset++
				if length == lenLimit {
					bt.son[ptr1] = bt.son[cyclicPos]
					bt.son[ptr0] = bt.son[cyclicPos+1]
					break
				}
			}
		}

		if bt.iw.buf[pby1+length] < bt.iw.buf[cur+length] {
			bt.son[ptr1] = curMatch
			ptr1 = cyclicPos + 1
			curMatch = bt.son[ptr1]
			len1 = length
		} else {
			bt.son[ptr0] = curMatch
			ptr0 = cyclicPos
			curMatch = bt.son[ptr0]
			len0 = length
		}
	}
	bt.movePos()
	return offset
}

func (bt *lzBinTree) skip(num uint32) {
	for i := uint32(0); i < num; i++ {
		var lenLimit uint32
		if bt.iw.pos+bt.matchMaxLen <= bt.iw.streamPos {
			lenLimit = bt.matchMaxLen
		} else {
			lenLimit = bt.iw.streamPos - bt.iw.pos
			if lenLimit < bt.kvMinMatchCheck {
				bt.movePos()
				continue
			}
		}

		matchMinPos := uint32(0)
		if bt.iw.pos > bt.cyclicBufSize {
			matchMinPos = bt.iw.pos - bt.cyclicBufSize
		}
		cur := bt.iw.bufOffset + bt.iw.pos
		var hashValue uint32
		if bt.hashArray == true {
			tmp := crcTable[bt.iw.buf[cur]] ^ uint32(bt.iw.buf[cur+1])
			hash2Value := tmp & (kHash2Size - 1)
			bt.hash[hash2Value] = bt.iw.pos
			tmp ^= uint32(bt.iw.buf[cur+2]) << 8
			hash3Value := tmp & (kHash3Size - 1)
			bt.hash[kHash3Offset+hash3Value] = bt.iw.pos
			hashValue = (tmp ^ crcTable[bt.iw.buf[cur+3]]<<5) & bt.hashMask
		} else {
			hashValue = uint32(bt.iw.buf[cur]) ^ uint32(bt.iw.buf[cur+1])<<8
		}

		curMatch := bt.hash[bt.kvFixHashSize+hashValue]
		bt.hash[bt.kvFixHashSize+hashValue] = bt.iw.pos
		ptr0 := bt.cyclicBufPos<<1 + 1
		ptr1 := bt.cyclicBufPos << 1
		len0 := bt.kvNumHashDirectBytes
		len1 := bt.kvNumHashDirectBytes
		count := bt.cutValue
		for {
			if curMatch <= matchMinPos || count == 0 {
				bt.son[ptr1] = kEmptyHashValue
				bt.son[ptr0] = kEmptyHashValue
				break
			}
			count--

			delta := bt.iw.pos - curMatch
			var cyclicPos uint32
			if delta <= bt.cyclicBufPos {
				cyclicPos = (bt.cyclicBufPos - delta) << 1
			} else {
				cyclicPos = (bt.cyclicBufPos - delta + bt.cyclicBufSize) << 1
			}
			pby1 := bt.iw.bufOffset + curMatch
			length := minUInt32(len0, len1)
			if bt.iw.buf[pby1+length] == bt.iw.buf[cur+length] {
				for length++; length != lenLimit; length++ {
					if bt.iw.buf[pby1+length] != bt.iw.buf[cur+length] {
						break
					}
				}
				if length == lenLimit {
					bt.son[ptr1] = bt.son[cyclicPos]
					bt.son[ptr0] = bt.son[cyclicPos+1]
					break
				}
			}

			if bt.iw.buf[pby1+length] < bt.iw.buf[cur+length] {
				bt.son[ptr1] = curMatch
				ptr1 = cyclicPos + 1
				curMatch = bt.son[ptr1]
				len1 = length
			} else {
				bt.son[ptr0] = curMatch
				ptr0 = cyclicPos
				curMatch = bt.son[ptr0]
				len0 = length
			}
		}
		bt.movePos()
	}
}


var crcTable []uint32 = make([]uint32, 256)

// should be called in the encoder's contructor
func initCrcTable() {
	for i := uint32(0); i < 256; i++ {
		r := i
		for j := 0; j < 8; j++ {
			if r&1 != 0 {
				r = r>>1 ^ 0xEDB88320
			} else {
				r >>= 1
			}
		}
		crcTable[i] = r
	}
}
