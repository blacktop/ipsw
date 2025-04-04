package iboot

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/lzfse-cgo"
)

const MinStringLength = 2

var (
	lzfseStart = []byte{0x62, 0x76, 0x78, 0x32} // bvx2
	lzfseEnd   = []byte{0x62, 0x76, 0x78, 0x24} // bvx$
	prologs    = [][]byte{
		{0x7F, 0x23, 0x03, 0xD5}, // PACIBSP
		{0xBD, 0xA9},             //
		{0xBF, 0xA9},             //
	}
)

type IBoot struct {
	Version     string
	Release     string
	Copyright   string
	BaseAddress uint64
	Strings     map[string]map[int64]string
	Files       map[string][]byte
}

func (i *IBoot) String() string {
	return fmt.Sprintf("%s %s (%s)", i.Version, i.Release, i.Copyright)
}

func Parse(data []byte) (*IBoot, error) {
	iboot := &IBoot{
		Strings: make(map[string]map[int64]string),
	}
	r := bytes.NewReader(data)

	var err error
	if _, err := r.Seek(0x200, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to copyright: %v", err)
	}
	iboot.Copyright, err = utils.ReadCString(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read copyright: %v", err)
	}
	if _, err := r.Seek(0x240, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to release string: %v", err)
	}
	iboot.Release, err = utils.ReadCString(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read release string: %v", err)
	}
	if _, err := r.Seek(0x280, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to version string: %v", err)
	}
	iboot.Version, err = utils.ReadCString(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read version string: %v", err)
	}

	iboot.BaseAddress, err = getBaseAddress(r)
	if err != nil {
		return nil, fmt.Errorf("failed to get base address: %v", err)
	}

	strs, err := dumpStrings(r, MinStringLength)
	if err != nil {
		return nil, fmt.Errorf("failed to dump strings: %v", err)
	}
	iboot.Strings["iboot"] = strs

	// extract files
	iboot.Files = make(map[string][]byte)
	found := 0
	var name string

	for {
		start := bytes.Index(data, lzfseStart)
		end := bytes.Index(data, lzfseEnd)

		if start < 0 || end < 0 {
			break
		}

		decomp := lzfse.DecodeBuffer(data[start : end+4])

		strs, err := dumpStrings(bytes.NewReader(decomp), MinStringLength)
		if err != nil {
			return nil, fmt.Errorf("failed to dump strings: %v", err)
		}
		// check for known files
		idx := bytes.Index(decomp, []byte("AppleSMCFirmware"))
		if idx > 0 {
			name = "AppleSMCFirmware.bin"
		} else {
			idx = bytes.Index(decomp, []byte("AppleStorageProcessorANS2"))
			if idx > 0 {
				name = "AppleStorageProcessorANS2.bin"
			} else {
				name = fmt.Sprintf("iboot_blob%02d.bin", found)
			}
		}

		iboot.Files[name] = decomp
		iboot.Strings[name] = strs

		found++
		data = data[end+4:]
	}

	return iboot, nil
}

func getBaseAddress(r *bytes.Reader) (uint64, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return 0, fmt.Errorf("failed to seek to base address: %v", err)
	}

	var startAddr uint64 = 0
	var instrValue uint32
	var results [1024]byte

	for {
		err := binary.Read(r, binary.LittleEndian, &instrValue)
		if err != nil {
			if err == io.EOF {
				break
			}
			return 0, fmt.Errorf("failed to read instruction @ %#x: %v", startAddr, err)
		}

		instruction, err := disassemble.Decompose(startAddr, instrValue, &results)
		if err != nil {
			return 0, fmt.Errorf("failed to decompose instruction @ %#x: %v", startAddr, err)
		}

		if strings.Contains(instruction.Encoding.String(), "loadlit") {
			if _, err := r.Seek(int64(instruction.Operands[1].Immediate), io.SeekStart); err != nil {
				return 0, fmt.Errorf("failed to seek to base address: %v", err)
			}
			var baseAddr uint64
			if err := binary.Read(r, binary.LittleEndian, &baseAddr); err != nil {
				return 0, fmt.Errorf("failed to read base address: %v", err)
			}
			return baseAddr, nil
		}

		// fmt.Printf("%#08x:  %s\t%s\n", uint64(startAddr), disassemble.GetOpCodeByteString(instrValue), instruction)

		startAddr += uint64(binary.Size(uint32(0)))
	}

	return 0, fmt.Errorf("failed to find base address")
}

func dumpStrings(r *bytes.Reader, minLen int) (map[int64]string, error) {
	var currentString bytes.Buffer
	var startOffset int64
	strings := make(map[int64]string)
	for {
		b, err := r.ReadByte()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to read byte: %v", err)
		}
		if isPrintableASCII(b) {
			if currentString.Len() == 0 {
				curr, _ := r.Seek(0, io.SeekCurrent)
				startOffset = curr - 1 // Mark start when the first printable char is found
			}
			currentString.WriteByte(b)
		} else {
			// Non-printable character encountered
			if currentString.Len() >= minLen {
				strings[startOffset] = currentString.String()
			}
			currentString.Reset()
			startOffset = -1
		}
	}

	return strings, nil
}

func isPrintableASCII(b byte) bool {
	return b >= 32 && b <= 126
}
