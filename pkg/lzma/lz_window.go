// Copyright (c) 2010, Andrei Vieru. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package lzma

import "io"

type lzOutWindow struct {
	w         io.Writer
	buf       []byte
	winSize   uint32
	pos       uint32
	streamPos uint32
	//unpacked  uint32 // counter of unpacked bytes
}

func newLzOutWindow(w io.Writer, windowSize uint32) *lzOutWindow {
	return &lzOutWindow{
		w:         w,
		buf:       make([]byte, windowSize),
		winSize:   windowSize,
		pos:       0,
		streamPos: 0,
		//unpacked:  0,
	}
}

func (ow *lzOutWindow) flush() {
	size := ow.pos - ow.streamPos
	if size == 0 {
		return
	}
	n, err := ow.w.Write(ow.buf[ow.streamPos : ow.streamPos+size])
	if err != nil {
		throw(err)
	}
	if uint32(n) != size {
		throw(nWriteError)
	}
	//unpacked += size
	if ow.pos >= ow.winSize {
		ow.pos = 0
	}
	ow.streamPos = ow.pos
}

func (ow *lzOutWindow) copyBlock(distance, length uint32) {
	pos := ow.pos - distance - 1
	if pos >= ow.winSize {
		pos += ow.winSize
	}
	for ; length != 0; length-- {
		if pos >= ow.winSize {
			pos = 0
		}
		ow.buf[ow.pos] = ow.buf[pos]
		ow.pos++
		pos++
		if ow.pos >= ow.winSize {
			ow.flush()
		}
	}
}

func (ow *lzOutWindow) putByte(b byte) {
	ow.buf[ow.pos] = b
	ow.pos++
	if ow.pos >= ow.winSize {
		ow.flush()
	}
}

func (ow *lzOutWindow) getByte(distance uint32) byte {
	pos := ow.pos - distance - 1
	if pos >= ow.winSize {
		pos += ow.winSize
	}
	return ow.buf[pos]
}

type lzInWindow struct {
	r              io.Reader
	buf            []byte
	posLimit       uint32
	lastSafePos    uint32
	bufOffset      uint32
	blockSize      uint32
	pos            uint32
	keepSizeBefore uint32
	keepSizeAfter  uint32
	streamPos      uint32
	streamEnd      bool
}

func newLzInWindow(r io.Reader, keepSizeBefore, keepSizeAfter, keepSizeReserv uint32) *lzInWindow {
	blockSize := keepSizeBefore + keepSizeAfter + keepSizeReserv
	iw := &lzInWindow{
		r:              r,
		buf:            make([]byte, blockSize),
		lastSafePos:    blockSize - keepSizeAfter,
		bufOffset:      0,
		blockSize:      blockSize,
		pos:            0,
		keepSizeBefore: keepSizeBefore,
		keepSizeAfter:  keepSizeAfter,
		streamPos:      0,
		streamEnd:      false,
	}
	iw.readBlock()
	return iw
}

func (iw *lzInWindow) moveBlock() {
	offset := iw.bufOffset + iw.pos - iw.keepSizeBefore
	if offset > 0 {
		offset--
	}
	numBytes := iw.bufOffset + iw.streamPos - offset
	for i := uint32(0); i < numBytes; i++ {
		iw.buf[i] = iw.buf[offset+i]
	}
	iw.bufOffset -= offset
}

func (iw *lzInWindow) readBlock() {
	if iw.streamEnd {
		return
	}
	for {
		if iw.blockSize-iw.bufOffset-iw.streamPos == 0 {
			return
		}
		n, err := iw.r.Read(iw.buf[iw.bufOffset+iw.streamPos : iw.blockSize])
		if err != nil && err != io.EOF {
			throw(err)
		}
		if n == 0 && err == io.EOF {
			iw.posLimit = iw.streamPos
			ptr := iw.bufOffset + iw.posLimit
			if ptr > iw.lastSafePos {
				iw.posLimit = iw.lastSafePos - iw.bufOffset
			}
			iw.streamEnd = true
			return
		}
		iw.streamPos += uint32(n)
		if iw.streamPos >= iw.pos+iw.keepSizeAfter {
			iw.posLimit = iw.streamPos - iw.keepSizeAfter
		}
	}
}

func (iw *lzInWindow) movePos() {
	iw.pos++
	if iw.pos > iw.posLimit {
		ptr := iw.bufOffset + iw.pos
		if ptr > iw.lastSafePos {
			iw.moveBlock()
		}
		iw.readBlock()
	}
}

func (iw *lzInWindow) getIndexByte(index int32) byte {
	return iw.buf[int32(iw.bufOffset+iw.pos)+index]
}

func (iw *lzInWindow) getMatchLen(index int32, distance, limit uint32) (res uint32) {
	uIndex := uint32(index)
	if iw.streamEnd == true {
		if iw.pos+uIndex+limit > iw.streamPos {
			limit = iw.streamPos - (iw.pos + uIndex)
		}
	}
	distance++
	pby := iw.bufOffset + iw.pos + uIndex
	for res = uint32(0); res < limit && iw.buf[pby+res] == iw.buf[pby+res-distance]; res++ {
		// empty body
	}
	return
}

func (iw *lzInWindow) getNumAvailableBytes() uint32 {
	return iw.streamPos - iw.pos
}

func (iw *lzInWindow) reduceOffsets(subValue uint32) {
	iw.bufOffset += subValue
	iw.posLimit -= subValue
	iw.pos -= subValue
	iw.streamPos -= subValue
}
