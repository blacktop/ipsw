// Copyright (c) 2010, Andrei Vieru. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The lzma package implements reading and writing of LZMA format compressed data.
// Reference implementation is LZMA SDK version 4.65 originaly developed by Igor
// Pavlov, available online at:
//
//  http://www.7-zip.org/sdk.html
//
//
//
// Usage examples. Write compressed data to a buffer:
//
//  var b bytes.Buffer
//  w := lzma.NewWriter(&b)
//  w.Write([]byte("hello, world\n"))
//  w.Close()
//
// read that data back:
//
//  r := lzma.NewReader(&b)
//  io.Copy(os.Stdout, r)
//  r.Close()
//
//
//
// If the data is bigger than you'd like to hold into memory, use pipes. Write
// compressed data to an io.PipeWriter:
//
//  pr, pw := io.Pipe()
//  go func() {
//  	defer pw.Close()
//	w := lzma.NewWriter(pw)
//	defer w.Close()
//	// the bytes.Buffer would be an io.Reader used to read uncompressed data from
//	io.Copy(w, bytes.NewBuffer([]byte("hello, world\n")))
//  }()
//
// and read it back:
//
//  defer pr.Close()
//  r := lzma.NewReader(pr)
//  defer r.Close()
//  // the os.Stdout would be an io.Writer used to write uncompressed data to
//  io.Copy(os.Stdout, r)
//
//
//
package lzma

import (
	"errors"
	"io"
)

const (
	inBufSize           = 1 << 16
	outBufSize          = 1 << 16
	lzmaPropSize        = 5
	lzmaHeaderSize      = lzmaPropSize + 8
	lzmaMaxReqInputSize = 20

	kNumRepDistances                = 4
	kNumStates                      = 12
	kNumPosSlotBits                 = 6
	kDicLogSizeMin                  = 0
	kNumLenToPosStatesBits          = 2
	kNumLenToPosStates              = 1 << kNumLenToPosStatesBits
	kMatchMinLen                    = 2
	kNumAlignBits                   = 4
	kAlignTableSize                 = 1 << kNumAlignBits
	kAlignMask                      = kAlignTableSize - 1
	kStartPosModelIndex             = 4
	kEndPosModelIndex               = 14
	kNumPosModels                   = kEndPosModelIndex - kStartPosModelIndex
	kNumFullDistances               = 1 << (kEndPosModelIndex / 2)
	kNumLitPosStatesBitsEncodingMax = 4
	kNumLitContextBitsMax           = 8
	kNumPosStatesBitsMax            = 4
	kNumPosStatesMax                = 1 << kNumPosStatesBitsMax
	kNumLowLenBits                  = 3
	kNumMidLenBits                  = 3
	kNumHighLenBits                 = 8
	kNumLowLenSymbols               = 1 << kNumLowLenBits
	kNumMidLenSymbols               = 1 << kNumMidLenBits
	kNumLenSymbols                  = kNumLowLenSymbols + kNumMidLenSymbols + (1 << kNumHighLenBits)
	kMatchMaxLen                    = kMatchMinLen + kNumLenSymbols - 1
)

// A streamError reports the presence of corrupt input stream.
var streamError = errors.New("error in lzma encoded data stream")

// A headerError reports an error in the header of the lzma encoder file.
var headerError = errors.New("error in lzma header")

// A nWriteError reports what its message reads
var nWriteError = errors.New("number of bytes returned by Writer.Write() didn't meet expectances")

// TODO: implement this err
// A dataIntegrityError reports an error encountered while cheching data integrity.
// -- from lzma.txt:
// You can use multiple checks to test data integrity after full decompression:
// 1) Check Result and "status" variable.
// 2) Check that output(destLen) = uncompressedSize, if you know real uncompressedSize.
// 3) Check that output(srcLen) = compressedSize, if you know real compressedSize.
//     You must use correct finish mode in that case.
//
//type dataIntegrityError struct {
//	msg string
//	// hz
//}

func stateUpdateChar(index uint32) uint32 {
	if index < 4 {
		return 0
	}
	if index < 10 {
		return index - 3
	}
	return index - 6
}

func stateUpdateMatch(index uint32) uint32 {
	if index < 7 {
		return 7
	}
	return 10
}

func stateUpdateRep(index uint32) uint32 {
	if index < 7 {
		return 8
	}
	return 11
}

func stateUpdateShortRep(index uint32) uint32 {
	if index < 7 {
		return 9
	}
	return 11
}

func stateIsCharState(index uint32) bool {
	if index < 7 {
		return true
	}
	return false
}

func getLenToPosState(length uint32) uint32 {
	length -= kMatchMinLen
	if length < kNumLenToPosStates {
		return length
	}
	return kNumLenToPosStates - 1
}

// LZMA compressed file format
// ---------------------------
// Offset Size 	      Description
//   0     1   		Special LZMA properties (lc,lp, pb in encoded form)
//   1     4   		Dictionary size (little endian)
//   5     8   		Uncompressed size (little endian). Size -1 stands for unknown size

// lzma properties
type props struct {
	litContextBits, // lc
	litPosStateBits, // lp
	posStateBits uint8 // pb
	dictSize uint32
}

func (p *props) decodeProps(buf []byte) {
	d := buf[0]
	if d > (9 * 5 * 5) {
		throw(headerError)
	}
	p.litContextBits = d % 9
	d /= 9
	p.posStateBits = d / 5
	p.litPosStateBits = d % 5
	if p.litContextBits > kNumLitContextBitsMax || p.litPosStateBits > 4 || p.posStateBits > kNumPosStatesBitsMax {
		throw(headerError)
	}
	for i := 0; i < 4; i++ {
		p.dictSize += uint32(buf[i+1]) << uint32(i*8)
	}
}

type decoder struct {
	// i/o
	rd     *rangeDecoder // r
	outWin *lzOutWindow  // w

	// lzma header
	prop       *props
	unpackSize int64

	// hz
	matchDecoders    []uint16
	repDecoders      []uint16
	repG0Decoders    []uint16
	repG1Decoders    []uint16
	repG2Decoders    []uint16
	rep0LongDecoders []uint16
	posSlotCoders    []*rangeBitTreeCoder
	posDecoders      []uint16
	posAlignCoder    *rangeBitTreeCoder
	lenCoder         *lenCoder
	repLenCoder      *lenCoder
	litCoder         *litCoder
	dictSizeCheck    uint32
	posStateMask     uint32
}

func (z *decoder) doDecode() {
	var state uint32 = 0
	var rep0 uint32 = 0
	var rep1 uint32 = 0
	var rep2 uint32 = 0
	var rep3 uint32 = 0
	var nowPos uint64 = 0
	var prevByte byte = 0

	for z.unpackSize < 0 || int64(nowPos) < z.unpackSize {
		posState := uint32(nowPos) & z.posStateMask
		if z.rd.decodeBit(z.matchDecoders, state<<kNumPosStatesBitsMax+posState) == 0 {
			lsc := z.litCoder.getSubCoder(uint32(nowPos), prevByte)
			if !stateIsCharState(state) {
				prevByte = lsc.decodeWithMatchByte(z.rd, z.outWin.getByte(rep0))
			} else {
				prevByte = lsc.decodeNormal(z.rd)
			}
			z.outWin.putByte(prevByte)
			state = stateUpdateChar(state)
			nowPos++
		} else {
			var length uint32
			if z.rd.decodeBit(z.repDecoders, state) == 1 {
				length = 0
				if z.rd.decodeBit(z.repG0Decoders, state) == 0 {
					if z.rd.decodeBit(z.rep0LongDecoders, state<<kNumPosStatesBitsMax+posState) == 0 {
						state = stateUpdateShortRep(state)
						length = 1
					}
				} else {
					var distance uint32
					if z.rd.decodeBit(z.repG1Decoders, state) == 0 {
						distance = rep1
					} else {
						if z.rd.decodeBit(z.repG2Decoders, state) == 0 {
							distance = rep2
						} else {
							distance, rep3 = rep3, rep2
						}
						rep2 = rep1
					}
					rep1, rep0 = rep0, distance
				}
				if length == 0 {
					length = z.repLenCoder.decode(z.rd, posState) + kMatchMinLen
					state = stateUpdateRep(state)
				}
			} else {
				rep3, rep2, rep1 = rep2, rep1, rep0
				length = z.lenCoder.decode(z.rd, posState) + kMatchMinLen
				state = stateUpdateMatch(state)
				posSlot := z.posSlotCoders[getLenToPosState(length)].decode(z.rd)
				if posSlot >= kStartPosModelIndex {
					numDirectBits := posSlot>>1 - 1
					rep0 = (2 | posSlot&1) << numDirectBits
					if posSlot < kEndPosModelIndex {
						rep0 += reverseDecodeIndex(z.rd, z.posDecoders, rep0-posSlot-1, numDirectBits)
					} else {
						rep0 += z.rd.decodeDirectBits(numDirectBits-kNumAlignBits) << kNumAlignBits
						rep0 += z.posAlignCoder.reverseDecode(z.rd)
						if int32(rep0) < 0 {
							if rep0 == 0xFFFFFFFF {
								break
							}
							throw(streamError)
						}
					}
				} else {
					rep0 = posSlot
				}
			}
			if uint64(rep0) >= nowPos || rep0 >= z.dictSizeCheck {
				throw(streamError)
			}
			z.outWin.copyBlock(rep0, length)
			nowPos += uint64(length)
			prevByte = z.outWin.getByte(0)
		}
	}
	z.outWin.flush()
	//if z.unpackSize != -1 {
	//	if z.outWin.unpacked != z.unpackSize {
	//		throw(&dataIntegrityError{})
	//	}
	//}
}

func (z *decoder) decoder(r io.Reader, w io.Writer) (err error) {
	defer handlePanics(&err)

	// read 13 bytes (lzma header)
	header := make([]byte, lzmaHeaderSize)
	_, err = io.ReadFull(r, header)
	if err != nil {
		return
	}
	z.prop = &props{}
	z.prop.decodeProps(header)

	z.unpackSize = 0
	for i := 0; i < 8; i++ {
		b := header[lzmaPropSize+i]
		z.unpackSize = z.unpackSize | int64(b)<<uint64(8*i)
	}

	// do not move before r.Read(header)
	z.rd = newRangeDecoder(r)

	z.dictSizeCheck = maxUInt32(z.prop.dictSize, 1)
	z.outWin = newLzOutWindow(w, maxUInt32(z.dictSizeCheck, 1<<12))

	z.litCoder = newLitCoder(uint32(z.prop.litPosStateBits), uint32(z.prop.litContextBits))
	z.lenCoder = newLenCoder(uint32(1 << z.prop.posStateBits))
	z.repLenCoder = newLenCoder(uint32(1 << z.prop.posStateBits))
	z.posStateMask = uint32(1<<z.prop.posStateBits - 1)
	z.matchDecoders = initBitModels(kNumStates << kNumPosStatesBitsMax)
	z.repDecoders = initBitModels(kNumStates)
	z.repG0Decoders = initBitModels(kNumStates)
	z.repG1Decoders = initBitModels(kNumStates)
	z.repG2Decoders = initBitModels(kNumStates)
	z.rep0LongDecoders = initBitModels(kNumStates << kNumPosStatesBitsMax)
	z.posDecoders = initBitModels(kNumFullDistances - kEndPosModelIndex)
	z.posSlotCoders = make([]*rangeBitTreeCoder, kNumLenToPosStates)
	for i := 0; i < kNumLenToPosStates; i++ {
		z.posSlotCoders[i] = newRangeBitTreeCoder(kNumPosSlotBits)
	}
	z.posAlignCoder = newRangeBitTreeCoder(kNumAlignBits)

	z.doDecode()
	return
}

// NewReader returns a new ReadCloser that can be used to read the uncompressed
// version of r. It is the caller's responsibility to call Close on the ReadCloser
// when finished reading.
//
func NewReader(r io.Reader) io.ReadCloser {
	var z decoder
	pr, pw := io.Pipe()
	go func() {
		err := z.decoder(r, pw)
		pw.CloseWithError(err)
	}()
	return pr
}
