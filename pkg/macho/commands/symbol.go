package commands

import "github.com/blacktop/ipsw/pkg/macho/types"

// A Symbol is a Mach-O 32-bit or 64-bit symbol table entry.
type Symbol struct {
	Name  string
	Type  types.NLType
	Sect  uint8
	Desc  uint16
	Value uint64
}
