package dyld

import (
	"bytes"
	"fmt"
	"io"

	"github.com/apex/log"
	"github.com/pkg/errors"
)

type trieEntry struct {
	Name         string
	Flags        CacheExportFlag
	Other        uint64
	Address      uint64
	FoundInDylib string
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

func (e trieEntry) String() string {
	if len(e.FoundInDylib) > 0 {
		return fmt.Sprintf("0x%8x: %s, %s", e.Address, e.Name, e.FoundInDylib)
	}
	return fmt.Sprintf("0x%8x: %s", e.Address, e.Name)
}

func readUleb128(r *bytes.Reader) (uint64, error) {
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

func readUleb128FromBuffer(buf *bytes.Buffer) (uint64, int, error) {

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

func parseTrie(trieData []byte, loadAddress uint64) ([]trieEntry, error) {

	var tNode trieNode
	var entries []trieEntry

	nodes := []trieNode{trieNode{
		Offset:   0,
		SymBytes: make([]byte, 0),
	}}

	r := bytes.NewReader(trieData)

	for len(nodes) > 0 {
		tNode, nodes = nodes[len(nodes)-1], nodes[:len(nodes)-1]

		r.Seek(int64(tNode.Offset), io.SeekStart)

		terminalSize, err := readUleb128(r)
		if err != nil {
			return nil, err
		}

		if terminalSize != 0 {
			var symFlagInt, symValueInt, symOtherInt uint64
			var reExportSymBytes []byte
			var symName string

			symFlagInt, err := readUleb128(r)
			if err != nil {
				return nil, err
			}

			flags := CacheExportFlag(symFlagInt)

			if flags.ReExport() {
				symOtherInt, err = readUleb128(r)
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
					reExportSymBytes = append(reExportSymBytes, s)
				}
			}

			symValueInt, err = readUleb128(r)
			if err != nil {
				return nil, err
			}

			if flags.StubAndResolver() {
				symOtherInt, err = readUleb128(r)
				if err != nil {
					return nil, err
				}
				// TODO: handle stubs
				log.Debugf("StubAndResolver: %d", symOtherInt)
			}

			if flags.Regular() || flags.ThreadLocal() {
				symValueInt += loadAddress
			}

			if len(reExportSymBytes) > 0 {
				symName = fmt.Sprintf("%s (%s)", string(tNode.SymBytes), string(reExportSymBytes))
			} else {
				symName = fmt.Sprintf("%s", string(tNode.SymBytes))
			}

			entries = append(entries, trieEntry{
				Name:    symName,
				Flags:   flags,
				Other:   symOtherInt,
				Address: symValueInt,
			})
		}

		r.Seek(int64(tNode.Offset+terminalSize+1), io.SeekStart)
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

			childNodeOffset, err := readUleb128(r)
			if err != nil {
				return nil, err
			}

			// log.WithFields(log.Fields{
			// 	"name":   string(tmp),
			// 	"offset": childNodeOffset,
			// }).Infof("Node")
			nodes = append(nodes, trieNode{
				Offset:   childNodeOffset,
				SymBytes: tmp,
			})
		}

	}

	return entries, nil
}

func walkTrie(data []byte, symbol string) (uint64, error) {

	var strIndex int
	var offset, nodeOffset uint64

	r := bytes.NewReader(data)

	for {
		r.Seek(int64(offset), io.SeekStart)

		terminalSize, err := readUleb128(r)
		if err != nil {
			return 0, err
		}

		if int(strIndex) == len(symbol) && (terminalSize != 0) {
			// skip over zero terminator
			return offset + 1, nil
		}

		r.Seek(int64(offset+terminalSize+1), io.SeekStart)

		childrenRemaining, err := r.ReadByte()
		if err == io.EOF {
			break
		}

		nodeOffset = 0

		for i := childrenRemaining; i > 0; i-- {
			searchStrIndex := strIndex
			wrongEdge := false

			for {
				c, err := r.ReadByte()
				if err == io.EOF {
					break
				}
				if c == '\x00' || searchStrIndex == len(symbol) {
					break
				}
				if !wrongEdge {
					if c != symbol[searchStrIndex] {
						wrongEdge = true
					}
					searchStrIndex++
				}
			}

			if wrongEdge {
				// advance to next child
				r.Seek(1, io.SeekCurrent) // skip over zero terminator
				// skip over last byte of uleb128
				_, err = readUleb128(r)
				if err != nil {
					return 0, err
				}
			} else {
				// the symbol so far matches this edge (child)
				// so advance to the child's node
				// r.Seek(1, io.SeekCurrent)
				nodeOffset, err = readUleb128(r)
				if err != nil {
					return 0, err
				}

				strIndex = searchStrIndex
				break
			}
		}

		if nodeOffset != 0 {
			offset = nodeOffset
		} else {
			break
		}
	}

	return offset, fmt.Errorf("symbol not in trie")
}
