package dyld

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/apex/log"
	"github.com/pkg/errors"
)

type trieEntry struct {
	Name   string
	Flags  CacheExportFlag
	Offset uint64
	Other  uint64
}

type trieEntrys struct {
	Entries           []trieEntry
	edgeStrings       [][]byte
	cummulativeString []byte
	r                 *bytes.Reader
}

type trieNode struct {
	Offset   uint64
	SymBytes []byte
}

func parseTrie(trieData []byte) ([]trieEntry, error) {

	var tNode trieNode
	var entries []trieEntry

	nodes := []trieNode{trieNode{
		Offset:   0,
		SymBytes: make([]byte, 0),
	}}

	r := bytes.NewReader(trieData)

	for len(nodes) > 0 {
		// pop last trieNode
		tNode, nodes = nodes[len(nodes)-1], nodes[:len(nodes)-1]

		terminalSize, err := ReadUleb128(r)
		if err != nil {
			return nil, err
		}

		if terminalSize != 0 {
			var symFlagInt, symValueInt, symOtherInt uint64

			symFlagInt, err := ReadUleb128(r)
			if err != nil {
				return nil, err
			}
			flags := CacheExportFlag(symFlagInt)
			fmt.Println(flags)
			if flags.ReExport() {
				var reExportSym []byte
				symOtherInt, err = ReadUleb128(r)
				if err != nil {
					return nil, err
				}
				for {
					s, err := r.ReadByte()
					if err == io.EOF {
						break
					}
					if s == '\x00' {
						break
					}
					reExportSym = append(reExportSym, s)
				}
			}

			symValueInt, err = ReadUleb128(r)
			if err != nil {
				return nil, err
			}

			if flags.StubAndResolver() {
				symOtherInt, err = ReadUleb128(r)
				if err != nil {
					return nil, err
				}
				fmt.Println(symOtherInt)
			}

			entries = append(entries, trieEntry{
				Name:   string(tNode.SymBytes),
				Flags:  flags,
				Offset: symValueInt,
				Other:  symOtherInt,
			})
		}

		r.Seek(int64(tNode.Offset+terminalSize), os.SEEK_CUR)
		childrenRemaining, err := r.ReadByte()
		if err == io.EOF {
			break
		}

		for i := 0; i < int(childrenRemaining); i++ {

			tmp := make([]byte, len(tNode.SymBytes), 32000)
			copy(tmp, tNode.SymBytes)

			for {
				s, err := r.ReadByte()
				if err == io.EOF {
					break
				}
				if s == '\x00' {
					break
				}
				tmp = append(tmp, s)
			}

			childNodeOffset, err := ReadUleb128(r)
			if err != nil {
				return nil, err
			}

			nodes = append(nodes, trieNode{
				Offset:   childNodeOffset,
				SymBytes: tmp,
			})
		}

	}

	return entries, nil
}

func ReadUleb128(r *bytes.Reader) (uint64, error) {
	var result uint64
	var shift uint64

	for {
		b, err := r.ReadByte()
		if err != nil {
			return 0, errors.Wrap(err, "could not parse ULEB128 value")
		}

		result |= uint64((uint(b) & 0x7f) << shift)

		// If high order bit is 1.
		if (b & 0x80) == 0 {
			break
		}

		shift += 7
	}

	return result, nil
}

func walkTrie(data []byte, symbol string) (int, error) {

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
			return -1, fmt.Errorf("malformed trie node, terminalSize=0x%x extends past end of trie", terminalSize)
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

func readSleb128(buf *bytes.Buffer) (int64, int, error) {

	var (
		b      byte
		err    error
		result int64
		shift  uint64
		length int
	)

	if buf.Len() == 0 {
		return 0, 0, nil
	}

	for {
		b, err = buf.ReadByte()
		if err != nil {
			return 0, 0, errors.Wrap(err, "could not parse SLEB128 value")
		}
		length++

		result |= int64((int64(b) & 0x7f) << shift)
		shift += 7
		if b&0x80 == 0 {
			break
		}
	}

	if (shift < 8*uint64(length)) && (b&0x40 > 0) {
		result |= -(1 << shift)
	}
	return result, length, nil
}
