/*
Copyright © 2018-2026 blacktop

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package kernel

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/blacktop/ipsw/pkg/kernelcache/cpp"
)

// methodSlotDTO is the per-slot JSON shape emitted by `ipsw kernel cpp --methods
// --json`. It uses lowercase tags and 0x-hex string addresses and is distinct
// from the []cpp.Class shape emitted by `ipsw kernel cpp --json`.
type methodSlotDTO struct {
	Index         int    `json:"index"`
	Offset        uint64 `json:"offset"`
	SlotAddr      string `json:"slot_addr"`
	Target        string `json:"target"`
	Symbol        string `json:"symbol,omitempty"`
	Method        string `json:"method,omitempty"`
	Class         string `json:"class,omitempty"`
	Mangled       string `json:"mangled,omitempty"`
	Auth          bool   `json:"auth"`
	PAC           uint16 `json:"pac"`
	PACHex        string `json:"pac_hex"`
	Key           uint8  `json:"key"`
	AddrDiv       bool   `json:"addr_div"`
	CacheLevel    uint8  `json:"cache_level"`
	PureVirtual   bool   `json:"pure_virtual,omitempty"`
	ExternalReloc bool   `json:"external_reloc,omitempty"`
	Structor      bool   `json:"structor,omitempty"`
	Overrides     bool   `json:"overrides,omitempty"`
	Authoritative bool   `json:"authoritative,omitempty"`
}

// methodTableDTO is the per-class method table JSON shape.
type methodTableDTO struct {
	Class      string          `json:"class"`
	Bundle     string          `json:"bundle,omitempty"`
	VtableAddr string          `json:"vtable_addr"`
	NumMethods int             `json:"num_methods"`
	Methods    []methodSlotDTO `json:"methods"`
}

func methodTableToDTO(mt cpp.MethodTable) methodTableDTO {
	dto := methodTableDTO{
		Class:      mt.Class,
		Bundle:     mt.Bundle,
		VtableAddr: fmt.Sprintf("%#x", mt.VtableAddr),
		NumMethods: mt.NumMethods(),
		Methods:    make([]methodSlotDTO, 0, len(mt.Methods)),
	}
	for _, e := range mt.Methods {
		dto.Methods = append(dto.Methods, methodSlotDTO{
			Index:         e.Index,
			Offset:        e.Offset,
			SlotAddr:      fmt.Sprintf("%#x", e.SlotAddress),
			Target:        fmt.Sprintf("%#x", e.Address),
			Symbol:        e.Symbol,
			Method:        e.Method,
			Class:         e.Class,
			Mangled:       e.Mangled,
			Auth:          e.Auth,
			PAC:           e.PAC,
			PACHex:        fmt.Sprintf("%#x", e.PAC),
			Key:           e.Key,
			AddrDiv:       e.AddrDiv,
			CacheLevel:    e.CacheLevel,
			PureVirtual:   e.PureVirtual,
			ExternalReloc: e.ExternalReloc,
			Structor:      e.Structor,
			Overrides:     e.Overrides,
			Authoritative: e.Authoritative,
		})
	}
	return dto
}

// writeMethodTables renders the PAC-annotated method tables, either as the
// per-slot DTO JSON or as a text listing.
//
// Method tables are built over allClasses (the full discovered set) so override,
// inheritance, and PAC-name back-propagation can resolve parent classes; the
// display filter (e.g. -c / --limit, captured in display) is applied only at
// emit time. Classes without a vtable have no virtual methods and are omitted.
func writeMethodTables(scanner *cpp.Scanner, allClasses, display []cpp.Class, out io.Writer, asJSON bool) error {
	tables := scanner.BuildNamedMethodTables(allClasses)
	byVtable := make(map[uint64]cpp.MethodTable, len(tables))
	for _, mt := range tables {
		if mt.VtableAddr != 0 {
			byVtable[mt.VtableAddr] = mt
		}
	}
	selected := make([]cpp.MethodTable, 0, len(display))
	for _, c := range display {
		if c.VtableAddr == 0 {
			continue
		}
		if mt, ok := byVtable[c.VtableAddr]; ok {
			selected = append(selected, mt)
		}
	}
	if asJSON {
		dtos := make([]methodTableDTO, 0, len(selected))
		for _, mt := range selected {
			dtos = append(dtos, methodTableToDTO(mt))
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(dtos)
	}
	for _, mt := range selected {
		if _, err := io.WriteString(out, formatMethodTable(mt)); err != nil {
			return err
		}
	}
	return nil
}

// formatMethodTable renders one class' method table as an indented text listing.
func formatMethodTable(mt cpp.MethodTable) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s vtab=%s methods=%d", colorClass(mt.Class), colorAddr("%#x", mt.VtableAddr), mt.NumMethods())
	if mt.Bundle != "" {
		fmt.Fprintf(&b, "\t(%s)", colorBundle(mt.Bundle))
	}
	b.WriteByte('\n')
	for _, e := range mt.Methods {
		fmt.Fprintf(&b, "  [%3d] +%s %s -> %s",
			e.Index, colorAddr("%#04x", e.Offset), colorAddr("%#x", e.SlotAddress), colorAddr("%#x", e.Address))
		fmt.Fprintf(&b, " %s", slotFlags(e))
		if name := methodDisplayName(e); name != "" {
			fmt.Fprintf(&b, " %s", name)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// slotFlags renders the compact per-slot classification flags.
func slotFlags(e cpp.VtableEntry) string {
	flags := make([]byte, 0, 4)
	if e.Auth {
		flags = append(flags, 'A')
	} else {
		flags = append(flags, '-')
	}
	if e.Overrides {
		flags = append(flags, 'O')
	} else {
		flags = append(flags, '-')
	}
	if e.Structor {
		flags = append(flags, 'S')
	} else {
		flags = append(flags, '-')
	}
	if e.PureVirtual {
		flags = append(flags, 'P')
	} else if e.ExternalReloc {
		flags = append(flags, 'X')
	} else {
		flags = append(flags, '-')
	}
	if e.Auth {
		return fmt.Sprintf("%s key=%d pac=%#x", string(flags), e.Key, e.PAC)
	}
	return string(flags)
}

// methodDisplayName prefers the resolved class-qualified method, then the
// demangled symbol.
func methodDisplayName(e cpp.VtableEntry) string {
	if e.Class != "" && e.Method != "" {
		return e.Class + "::" + e.Method
	}
	if e.Method != "" {
		return e.Method
	}
	return e.Symbol
}
