package cpp

import (
	"fmt"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/fixupchains"
)

// extractPACFromPointer extracts PAC diversity from a pointer
func extractPACFromPointer(m *macho.File, ptrAddr uint64) uint16 {
	if !m.HasFixups() {
		return 0
	}
	if offset, err := m.GetOffset(ptrAddr); err != nil {
		return 0
	} else {
		dcf, err := m.DyldChainedFixups()
		if err != nil {
			return 0
		}
		if fixup, err := dcf.GetFixupAtOffset(offset); err == nil && fixup != nil {
			if auth, ok := fixup.(fixupchains.Auth); ok {
				return uint16(auth.Diversity())
			}
		}
	}
	return 0
}

func resolveMethodName(m *macho.File, mi *Method, className string) {
	if m.Symtab != nil {
		for _, s := range m.Symtab.Syms {
			if s.Value == mi.Address {
				mi.Name = s.Name
				if mi.PAC == 0 {
					if pac, ok := computePAC(mi.Name); ok {
						mi.PAC = pac
					}
				}
				return
			}
		}
	}
	mi.Name = fmt.Sprintf("%s::fn_%x()", className, mi.Index)
}

func computePAC(sym string) (uint16, bool) {
	if len(sym) == 0 || sym[0] != '_' { // expect underscore
		return 0, false
	}
	s := sym[1:]
	n := len(s)
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			n = i
			break
		}
	}
	if n == 0 {
		return 0, false
	}
	h := siphash([]byte(s[:n]))
	return uint16(h%0xffff) + 1, true
}

func siphash(in []byte) uint64 {
	v0 := uint64(0x0a257d1c9bbab1c0)
	v1 := uint64(0xb0eef52375ef8302)
	v2 := uint64(0x1533771c85aca6d4)
	v3 := uint64(0xa0e4e32062ff891c)
	for i := 0; i+8 <= len(in); i += 8 {
		m := uint64(in[i+7])<<56 | uint64(in[i+6])<<48 | uint64(in[i+5])<<40 |
			uint64(in[i+4])<<32 | uint64(in[i+3])<<24 | uint64(in[i+2])<<16 |
			uint64(in[i+1])<<8 | uint64(in[i+0])
		v3 ^= m
		v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
		v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
		v0 ^= m
	}
	// Pack tail bytes in little-endian order (first tail byte → LSB)
	// tailStart is the offset where the incomplete 8-byte block begins
	tailStart := (len(in) / 8) * 8
	b := uint64(len(in)) << 56
	switch len(in) & 7 {
	case 7:
		b |= uint64(in[tailStart+6]) << 48
		fallthrough
	case 6:
		b |= uint64(in[tailStart+5]) << 40
		fallthrough
	case 5:
		b |= uint64(in[tailStart+4]) << 32
		fallthrough
	case 4:
		b |= uint64(in[tailStart+3]) << 24
		fallthrough
	case 3:
		b |= uint64(in[tailStart+2]) << 16
		fallthrough
	case 2:
		b |= uint64(in[tailStart+1]) << 8
		fallthrough
	case 1:
		b |= uint64(in[tailStart+0])
	}
	v3 ^= b
	v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
	v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
	v0 ^= b
	v2 ^= 0xff
	for i := 0; i < 4; i++ {
		v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
	}
	return v0 ^ v1 ^ v2 ^ v3
}

func rotl(x uint64, b uint) uint64 { return (x << b) | (x >> (64 - b)) }
func sipround(v0, v1, v2, v3 uint64) (uint64, uint64, uint64, uint64) {
	v0 += v1
	v1 = rotl(v1, 13) ^ v0
	v0 = rotl(v0, 32)
	v2 += v3
	v3 = rotl(v3, 16) ^ v2
	v0 += v3
	v3 = rotl(v3, 21) ^ v0
	v2 += v1
	v1 = rotl(v1, 17) ^ v2
	v2 = rotl(v2, 32)
	return v0, v1, v2, v3
}
