package adc

const DECOMP_RATIO = 10

// DecompressADC decompresses Apple Data Compression
func DecompressADC(src []byte) []byte {

	var ctl int
	var dist int
	var length int

	i := 0
	o := 0

	dst := make([]byte, 0, len(src)*DECOMP_RATIO)

	for {
		if i >= len(src) {
			break
		}
		if o >= len(dst) {
			break
		}

		ctl = int(src[i])
		i++

		if (ctl & 0x80) != 0 {
			length = int(ctl&0x7F) + 1
			for cnt := 0; cnt < length; cnt++ {
				dst[o] = src[i]
				o++
				i++
			}
		} else {
			if (ctl & 0x40) != 0 {
				length = int(ctl - 0x3C)
				dist = int(src[i])
				i++
				dist = (dist << 8) | int(src[i])
				dist++
				i++
			} else {
				length = (ctl>>2)&0xF + 3
				dist = (ctl&3)<<8 | int(src[i]) + 1
				i++
			}

			for cnt := 0; cnt < length; cnt++ {
				dst[o] = dst[o-dist]
				o++
			}
		}
	}

	return dst[:o]
}
