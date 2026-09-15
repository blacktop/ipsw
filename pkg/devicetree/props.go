package devicetree

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/blacktop/go-macho/types"
)

// Data is an undecoded property value; it marshals to JSON as base64.
type Data []byte

// String returns the base64 value followed by any embedded printable names (4+ chars).
func (d Data) String() string {
	enc := base64.StdEncoding.EncodeToString(d)
	var names []string
	for _, field := range bytes.FieldsFunc(d, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
		if len(field) >= 4 {
			names = append(names, string(field))
		}
	}
	if len(names) == 0 {
		return enc
	}
	return fmt.Sprintf("%s %q", enc, names)
}

// Function is a function-* property: a provider phandle, a FourCC function name and its arguments.
type Function struct {
	Phandle uint32   `json:"phandle"`
	Name    string   `json:"function"`
	Args    []uint32 `json:"args,omitempty"`
}

func (f Function) String() string {
	args := make([]string, 0, len(f.Args))
	for _, arg := range f.Args {
		args = append(args, fmt.Sprintf("%#x", arg))
	}
	return fmt.Sprintf("%d:%s(%s)", f.Phandle, f.Name, strings.Join(args, ", "))
}

// DAPFEntry is one DART address-filter (dapf-instance-*) entry.
//
// Layout credit: DAPFT8110 in https://github.com/AsahiLinux/m1n1/blob/main/proxyclient/m1n1/adt.py
type DAPFEntry struct {
	Start uint64    `json:"start"`
	End   uint64    `json:"end"`
	R20   uint32    `json:"r20"`
	Unk1  uint32    `json:"unk1"`
	R4    uint32    `json:"r4"`
	Unk2  [5]uint32 `json:"unk2"`
	Unk3  uint8     `json:"unk3"`
	R0h   uint8     `json:"r0h"`
	R0l   uint8     `json:"r0l"`
	Unk4  uint8     `json:"unk4"`
}

func (e DAPFEntry) String() string {
	return fmt.Sprintf("start=%#x end=%#x r20=%#x unk1=%#x r4=%#x unk2=%#x unk3=%#x r0h=%#x r0l=%#x unk4=%#x",
		e.Start, e.End, e.R20, e.Unk1, e.R4, e.Unk2, e.Unk3, e.R0h, e.R0l, e.Unk4)
}

// DAPFEntryB is the 56-byte DAPFT8110B layout with a trailing 32-bit pad.
type DAPFEntryB struct {
	DAPFEntry
	Pad uint32 `json:"pad"`
}

func (e DAPFEntryB) String() string {
	return fmt.Sprintf("%s pad=%#x", e.DAPFEntry, e.Pad)
}

// DAPFEntryC is the 55-byte DAPFT8110C layout with three trailing pad bytes.
type DAPFEntryC struct {
	DAPFEntry
	Pad [3]uint8 `json:"pad"`
}

func (e DAPFEntryC) String() string {
	return fmt.Sprintf("%s pad=[%#x %#x %#x]", e.DAPFEntry, e.Pad[0], e.Pad[1], e.Pad[2])
}

var propertyParsers = map[string]func([]byte) any{
	"model":                   parseCString,
	"cluster-type":            parseCString,
	"soc-generation":          parseCString,
	"compatible":              parseCompatible,
	"AAPL,phandle":            parseInt,
	"platform-name":           parsePlatformName,
	"pmap-io-ranges":          parsePmapIORanges,
	"ps-regs":                 parsePmgrMap,
	"devices":                 parsePmgrDevices,
	"regions":                 parseRegions,
	"reg-private":             parseAddr,
	"reg":                     parseReg,
	"sptm-allow-reg":          parseReg,
	"sptm-allow-internal-reg": parseReg,
	"uuid":                    parseUUID,
	"interrupts":              parseUint32s,
	"clock-gates":             parseUint32s,
	"power-gates":             parseUint32s,
	"service-gates":           parseUint32s,
	"clock-ids":               parseUint32s,
	"interrupt-parent":        parseUint32s,
	"iommu-parent":            parseUint32s,
}

func parseProperty(key, nodeName string, value []byte) any {
	switch {
	case key == "value" && strings.HasPrefix(nodeName, "__MACHO"):
		return parseOffSz(value)
	case key == "clocks" && nodeName == "pmgr":
		return parsePmgrClocks(value)
	case strings.HasPrefix(key, "function-"):
		return parseFunction(value)
	case strings.HasPrefix(key, "dapf-instance-"):
		return parseDAPF(value)
	case strings.HasPrefix(key, "special-region-") && strings.HasSuffix(key, "-frame"):
		return parseFloat32s(value)
	}
	if parse, ok := propertyParsers[key]; ok {
		return parse(value)
	}
	return parseValue(value)
}

// parseTemplate decodes a template (syscfg placeholder) property, which should be a C string.
func parseTemplate(value []byte) any {
	if str := bytes.TrimRight(value, "\x00"); len(str) > 0 && isPrintable(str) {
		return string(str)
	}
	return parseValue(value)
}

func parseCString(value []byte) any {
	str := bytes.TrimRight(value, "\x00")
	if len(str) == 0 || !isPrintable(str) {
		return undecoded(value)
	}
	return string(str)
}

// platform-name may be an empty fixed-width buffer.
func parsePlatformName(value []byte) any {
	str := bytes.TrimRight(value, "\x00")
	if !isPrintable(str) {
		return undecoded(value)
	}
	return string(str)
}

// parseCompatible decodes a NUL-separated string list, keeping empty entries.
func parseCompatible(value []byte) any {
	trimmed := bytes.TrimRight(value, "\x00")
	if len(trimmed) == 0 || len(trimmed) == len(value) {
		return parseValue(value)
	}
	parts := bytes.Split(trimmed, []byte("\x00"))
	list := make([]string, 0, len(parts))
	for _, part := range parts {
		if !isPrintable(part) {
			return parseValue(value)
		}
		list = append(list, string(part))
	}
	if len(list) == 1 {
		return list[0]
	}
	return list
}

func parseUUID(value []byte) any {
	if len(value) == 16 {
		return types.UUID(value).String()
	}
	return parseValue(value)
}

// undecoded is the fallback for known keys whose value does not match the expected layout.
func undecoded(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return Data(value)
}

func parseUint32s(value []byte) any {
	if len(value) == 0 || len(value)%4 != 0 {
		return undecoded(value)
	}
	vals := make([]uint32, len(value)/4)
	for i := range vals {
		vals[i] = binary.LittleEndian.Uint32(value[i*4:])
	}
	return vals
}

// parseFloat32s decodes float32 arrays; non-finite values are kept as Data because JSON cannot encode them.
func parseFloat32s(value []byte) any {
	if len(value) == 0 || len(value)%4 != 0 {
		return undecoded(value)
	}
	vals := make([]float32, len(value)/4)
	for i := range vals {
		vals[i] = math.Float32frombits(binary.LittleEndian.Uint32(value[i*4:]))
		if math.IsNaN(float64(vals[i])) || math.IsInf(float64(vals[i]), 0) {
			return Data(value)
		}
	}
	return vals
}

func parseDAPF(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	// Match m1n1's 52, 56, 55-byte precedence. Length alone is ambiguous
	// at common multiples (e.g. 728 bytes fits both the 52 and 56-byte layouts).
	var entries any
	switch {
	case len(value)%binary.Size(DAPFEntry{}) == 0:
		entries = make([]DAPFEntry, len(value)/binary.Size(DAPFEntry{}))
	case len(value)%binary.Size(DAPFEntryB{}) == 0:
		entries = make([]DAPFEntryB, len(value)/binary.Size(DAPFEntryB{}))
	case len(value)%binary.Size(DAPFEntryC{}) == 0:
		entries = make([]DAPFEntryC, len(value)/binary.Size(DAPFEntryC{}))
	default:
		return undecoded(value)
	}
	if err := binary.Read(bytes.NewReader(value), binary.LittleEndian, entries); err != nil {
		return Data(value)
	}
	return entries
}

// parseFunction decodes <phandle> <FourCC> <args...>. A lone 4-byte value is a FourCC when
// printable, else a phandle. Phandles are small integers, so a printable first word means
// another layout (e.g. FourCC-first values or function-perf-boost tables), which is kept as Data.
func parseFunction(value []byte) any {
	if len(value) == 0 || len(value)%4 != 0 {
		return undecoded(value)
	}
	if len(value) == 4 {
		if isPrintable(value) {
			return fourCC(value)
		}
		return Function{Phandle: binary.LittleEndian.Uint32(value)}
	}
	if isPrintable(value[:4]) || !isPrintable(value[4:8]) {
		return Data(value)
	}
	fn := Function{
		Phandle: binary.LittleEndian.Uint32(value[:4]),
		Name:    fourCC(value[4:8]),
	}
	for off := 8; off < len(value); off += 4 {
		fn.Args = append(fn.Args, binary.LittleEndian.Uint32(value[off:]))
	}
	return fn
}

func fourCC(value []byte) string {
	name := slices.Clone(value[:4])
	slices.Reverse(name)
	return string(name)
}

func isPrintable(value []byte) bool {
	for _, b := range value {
		if b < 0x20 || b > 0x7e {
			return false
		}
	}
	return true
}
