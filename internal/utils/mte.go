package utils

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/go-macho"
)

// mteMnemonics is the complete list of all MTE instruction mnemonics
var mteMnemonics = map[disassemble.Operation]bool{
	disassemble.ARM64_ADDG:  true, // Add with Tag
	disassemble.ARM64_SUBG:  true, // Subtract with Tag
	disassemble.ARM64_IRG:   true, // Insert Random Tag
	disassemble.ARM64_GMI:   true, // Tag Mask Insert
	disassemble.ARM64_LDG:   true, // Load Allocation Tag
	disassemble.ARM64_STG:   true, // Store Allocation Tag
	disassemble.ARM64_ST2G:  true, // Store Allocation Tags
	disassemble.ARM64_STZG:  true, // Store Allocation Tag and Zero
	disassemble.ARM64_STZ2G: true, // Store Allocation Tags and Zero
	disassemble.ARM64_STGP:  true, // Store Allocation Tag and Pair
	disassemble.ARM64_LDGM:  true, // Load Tag Multiple
	disassemble.ARM64_STGM:  true, // Store Tag Multiple
	disassemble.ARM64_STZGM: true, // Store Tag and Zero Multiple
	disassemble.ARM64_SUBP:  true, // Subtract Pointer
	disassemble.ARM64_SUBPS: true, // Subtract Pointer, setting Flags
	disassemble.ARM64_CMPP:  true, // Compare Pointer (alias of SUBPS)
}

// HasMTEInstructions scans a Mach-O file for MTE (Memory Tagging Extension) instructions.
// Returns true and the first address if any MTE instructions are found in the executable sections.
func HasMTEInstructions(m *macho.File) (bool, uint64) {
	var instrValue uint32
	var buffer [1024]byte

	sections := m.GetSectionsForSegment("__TEXT")
	if len(sections) == 0 {
		return false, 0
	}

	for _, sec := range sections {
		if !sec.Flags.IsPureInstructions() && !sec.Flags.IsSomeInstructions() {
			continue
		}

		data := make([]byte, sec.Size)
		if _, err := m.ReadAtAddr(data, sec.Addr); err != nil {
			continue
		}

		r := bytes.NewReader(data)
		startAddr := sec.Addr

		for {
			err := binary.Read(r, binary.LittleEndian, &instrValue)

			if err == io.EOF {
				break
			}

			inst, err := disassemble.Decompose(startAddr, instrValue, &buffer)
			if err != nil || inst == nil {
				startAddr += uint64(binary.Size(uint32(0)))
				continue
			}

			if isMTE, found := mteMnemonics[inst.Operation]; found {
				return isMTE, startAddr
			}

			startAddr += uint64(binary.Size(uint32(0)))
		}
	}

	return false, 0
}
