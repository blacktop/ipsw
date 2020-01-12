package dyld

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/apex/log"
	"github.com/pkg/errors"
)

type TrieEntry struct {
	Name       uint64 // const char*
	Address    uint64
	Flags      uint64
	Other      uint64
	ImportName uint64 // const char*
}

func readUleb128(buf *bytes.Buffer) (uint64, int, error) {

	var (
		result uint64
		shift  uint64
		length int
	)

	if buf.Len() == 0 {
		return 0, 0, nil
	}

	for {
		b, err := buf.ReadByte()
		if err != nil {
			return 0, 0, errors.Wrap(err, "could not parse ULEB128 value")
		}
		length++

		result |= uint64((uint(b) & 0x7f) << shift)

		// If high order bit is 1.
		if (b & 0x80) == 0 {
			break
		}

		shift += 7
	}

	return result, length, nil
}

// Walk walks a trie searching for a string
func Walk(data []byte, symbol string) (int, error) {

	var offset int
	var strIndex uint8
	var children, childrenRemaining uint8
	var terminalSize, nodeOffset uint64

	buff := bytes.NewReader(data)

	for {
		b := make([]byte, binary.Size(terminalSize))
		_, err := buff.ReadAt(b, int64(offset))
		if err != nil {
			return -1, errors.Wrap(err, "failed to read trie terminalSize")
		}
		terminalSize := binary.LittleEndian.Uint64(b)
		offset++

		if terminalSize > 127 {
			// except for re-export-with-rename, all terminal sizes fit in one byte
			offset--
			var n int
			terminalSize, n, err = readUleb128(bytes.NewBuffer(data[offset:]))
			if err != nil {
				return -1, errors.Wrap(err, "failed to read terminalSize Uleb128")
			}
			offset += n
		}

		if int(strIndex) >= len(symbol) && (terminalSize != 0) {
			return offset, nil
		}

		children = data[uint64(offset)+terminalSize]
		if int(children) > len(data) {
			return -1, fmt.Errorf("malformed trie node, terminalSize=0x%lx extends past end of trie", terminalSize)
		}

		childrenRemaining = data[uint64(offset)+terminalSize+1]

		offset = int(uint64(offset) + terminalSize + 1)
		nodeOffset = 0

		for i := childrenRemaining; i > 0; i-- {
			searchStrIndex := strIndex
			line, err := bytes.NewBuffer(data[offset:]).ReadString(byte(0))
			if err != nil {
				return -1, errors.Wrap(err, "failed to read child string")
			}
			log.Debugf("trieWalk: child str=%s", line)

			wrongEdge := false
			// scan whole edge to get to next edge
			// if edge is longer than target symbol name, don't read past end of symbol name
			c := data[offset]
			for c != '\x00' {
				if !wrongEdge {
					if c != symbol[searchStrIndex] {
						wrongEdge = true
					}
					searchStrIndex++
				}
				offset++
				c = data[offset]
			}
			if wrongEdge {
				// advance to next child
				offset++ // skip over zero terminator
				// skip over uleb128 until last byte is found
				for (data[offset] & 0x80) != 0 {
					offset++
				}
				offset++ // skip over last byte of uleb128

				if offset > len(data) {
					return -1, fmt.Errorf("malformed trie node, child node extends past end of trie")
				}
			} else {
				// the symbol so far matches this edge (child)
				// so advance to the child's node
				offset++
				var n int
				nodeOffset, n, err = readUleb128(bytes.NewBuffer(data[offset:]))
				if err != nil {
					return -1, errors.Wrap(err, "failed to read nodeOffset Uleb128")
				}
				offset += n

				if (nodeOffset == 0) || (len(data) < int(nodeOffset)) {
					return -1, fmt.Errorf("malformed trie child, nodeOffset=0x%lx out of range", nodeOffset)
				}
				// TODO: find out why we need this (we shouldn't)
				if strIndex == searchStrIndex {
					return -1, fmt.Errorf("symbol not in trie")
				}
				strIndex = searchStrIndex
				log.Debugf("trieWalk: found matching edge advancing to node 0x%x", nodeOffset)
				break
			}
		}

		if nodeOffset != 0 {
			offset = int(nodeOffset)
		} else {
			break
		}

	}

	return offset, fmt.Errorf("symbol not in trie")
}
