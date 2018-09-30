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

	// ring buffer of size N, with extra F-1 bytes to aid string comparison
	textBuf := make([]byte, N+F-1)
	srcBuf := bytes.NewBuffer(src)
	dst := bytes.Buffer{}

	var i, j, r, c int
	var flags uint

	r = N - F
	flags = 0

	for {
		flags >>= 1

		if (flags & 0x100) == 0 {
			bite, err := srcBuf.ReadByte()
			if err != nil {
				break
			}
			c = int(bite)
			flags = uint(c | 0xFF00) /* uses higher byte cleverly */
		} /* to count eight */

		if flags&1 != 0 {
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
				r++
				textBuf[r] = byte(c)
				r &= (N - 1)
			}
		}
	}

	return dst.Bytes()
}
