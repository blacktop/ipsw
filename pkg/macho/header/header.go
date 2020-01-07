package header

import (
	"fmt"

	"github.com/blacktop/ipsw/pkg/macho/utils"
)

// A FileHeader represents a Mach-O file header.
type FileHeader struct {
	Magic  Magic
	CPU    CPU
	SubCPU CPUSubtype
	Type   Type
	Ncmd   uint32
	Cmdsz  uint32
	Flags  Flag
}

const (
	FileHeaderSize32 = 7 * 4
	FileHeaderSize64 = 8 * 4
)

type Magic uint32

const (
	Magic32  Magic = 0xfeedface
	Magic64  Magic = 0xfeedfacf
	MagicFat Magic = 0xcafebabe
)

var magicStrings = []utils.IntName{
	{uint32(Magic32), "32-bit MachO"},
	{uint32(Magic64), "64-bit MachO"},
	{uint32(MagicFat), "Fat MachO"},
}

func (i Magic) Int() uint32      { return uint32(i) }
func (i Magic) String() string   { return utils.StringName(uint32(i), magicStrings, false) }
func (i Magic) GoString() string { return utils.StringName(uint32(i), magicStrings, true) }

func (h FileHeader) String() string {

	return fmt.Sprintf(
		"Magic         = %s\n"+
			"Type          = %s\n"+
			"CPU           = %s, %s\n"+
			"Commands      = %d (Size: %d)\n"+
			"Flags         = %s\n",
		h.Magic,
		h.Type,
		h.CPU, h.SubCPU.String(h.CPU),
		h.Ncmd,
		h.Cmdsz,
		h.Flags.Flags(),
	)
}
