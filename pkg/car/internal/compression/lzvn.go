package compression

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// lzvnSize walks instructions without expanding literals or matches. This
// validates the entire stream and determines an exact allocation before the
// native decoder runs once. Opcode fields follow Apple's LZVN format:
// https://github.com/lzfse/lzfse/blob/master/src/lzvn_decode_base.c
func lzvnSize(data []byte, limit int) (int, error) {
	size, distance := 0, 0
	for len(data) >= 8 {
		op := data[0]
		header, literal, match := 1, 0, 0
		switch {
		case op == 6:
			if len(data) != 8 || !bytes.Equal(data[1:], make([]byte, 7)) || size == 0 {
				return 0, fmt.Errorf("invalid LZVN end marker or trailing data")
			}
			return size, nil
		case op == 0x0e || op == 0x16: // NOP
		case op >= 0xe0: // Literal-only or match-only instruction.
			length := int(op & 15)
			if length == 0 {
				header, length = 2, int(data[1])+16
			}
			if op < 0xf0 {
				literal = length
			} else {
				match = length
			}
		case op >= 0xa0 && op <= 0xbf: // Medium distance.
			header, literal = 3, int(op>>3&3)
			word := int(binary.LittleEndian.Uint16(data[1:]))
			match, distance = int(op&7)*4+(word&3)+3, word>>2
		case op >= 0x70 && op <= 0x7f || op >= 0xd0 && op <= 0xdf:
			return 0, fmt.Errorf("undefined LZVN opcode %#x", op)
		default: // Literal and match, with small, large or previous distance.
			literal, match = int(op>>6), int(op>>3&7)+3
			switch op & 7 {
			case 6:
				if op < 0x40 {
					return 0, fmt.Errorf("undefined LZVN opcode %#x", op)
				}
			case 7:
				header, distance = 3, int(binary.LittleEndian.Uint16(data[1:]))
			default:
				header, distance = 2, int(op&7)*256+int(data[1])
			}
		}
		if len(data)-header < literal {
			return 0, fmt.Errorf("truncated LZVN literal")
		}
		if literal > limit-size || match > limit-size-literal {
			return 0, fmt.Errorf("LZVN output exceeds limit")
		}
		size += literal
		if match != 0 && (distance == 0 || distance > size) {
			return 0, fmt.Errorf("invalid LZVN match distance %d", distance)
		}
		size += match
		data = data[header+literal:]
	}
	return 0, fmt.Errorf("truncated LZVN stream")
}
