// Copyright © 2018 blacktop
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package lzss

import "bytes"

const (
	// N is the size of ring buffer - must be power of 2
	N = 4096
	// F is the upper limit for match_length
	F = 18
	// THRESHOLD encode string into position and length if match_length is greater than this
	THRESHOLD = 2
)

// Decompress decompresses lzss data
func Decompress(src []byte) []byte {

	var i, j, r, c int
	var flags uint

	srcBuf := bytes.NewBuffer(src)
	dst := bytes.Buffer{}

	// ring buffer of size N, with extra F-1 bytes to aid string comparison
	textBuf := make([]byte, N+F-1)

	r = N - F
	flags = 0

	for {
		flags = flags >> 1
		if ((flags) & 0x100) == 0 {
			bite, err := srcBuf.ReadByte()
			if err != nil {
				break
			}
			c = int(bite)
			flags = uint(c | 0xFF00) /* uses higher byte cleverly to count eight*/
		}
		if flags&1 == 1 {
			bite, err := srcBuf.ReadByte()
			if err != nil {
				break
			}
			c = int(bite)
			dst.WriteByte(byte(c))
			textBuf[r] = byte(c)
			r++
			r &= (N - 1)
		} else {
			bite, err := srcBuf.ReadByte()
			if err != nil {
				break
			}
			i = int(bite)

			bite, err = srcBuf.ReadByte()
			if err != nil {
				break
			}
			j = int(bite)

			i |= ((j & 0xF0) << 4)
			j = (j & 0x0F) + THRESHOLD
			for k := 0; k <= j; k++ {
				c = int(textBuf[(i+k)&(N-1)])
				dst.WriteByte(byte(c))
				textBuf[r] = byte(c)
				r++
				r &= (N - 1)
			}
		}
	}

	return dst.Bytes()
}
