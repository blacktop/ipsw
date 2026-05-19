package kalloctype

import (
	"io"
	"sort"
	"strconv"
	"strings"
)

const (
	KindFixed     = "fixed"
	KindVar       = "var"
	KindCollision = "collision"
)

type Record struct {
	Kind          string
	Name          string
	Signature     string
	Size          uint32
	Flags         uint32
	FlagsDecoded  []string
	Site          uint64
	HdrSignature  string
	ElemSignature string
}

type Collision struct {
	Size      uint32
	Signature string
	Types     []string
}

type flagDef struct {
	value uint32
	name  string
}

var flagDefs = [...]flagDef{
	{value: 0x0001, name: "DEFAULT"},
	{value: 0x0002, name: "PRIV_ACCT"},
	{value: 0x0004, name: "SHARED_ACCT"},
	{value: 0x0008, name: "DATA_ONLY"},
	{value: 0x0010, name: "VM"},
	{value: 0x0020, name: "CHANGED"},
	{value: 0x0040, name: "CHANGED2"},
	{value: 0x0080, name: "PTR_ARRAY"},
	{value: 0x2000, name: "NOEARLY"},
	{value: 0x4000, name: "SLID"},
	{value: 0x8000, name: "PROCESSED"},
}

func WriteJSONL(w io.Writer, records []Record) error {
	SortRecords(records)
	for _, rec := range records {
		if _, err := w.Write(rec.AppendJSON(nil)); err != nil {
			return err
		}
		if _, err := io.WriteString(w, "\n"); err != nil {
			return err
		}
	}
	return nil
}

func WriteCollisionJSONL(w io.Writer, collisions []Collision) error {
	SortCollisions(collisions)
	for _, collision := range collisions {
		if _, err := w.Write(collision.AppendJSON(nil)); err != nil {
			return err
		}
		if _, err := io.WriteString(w, "\n"); err != nil {
			return err
		}
	}
	return nil
}

func SortRecords(records []Record) {
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].Size != records[j].Size {
			return records[i].Size < records[j].Size
		}
		if records[i].Signature != records[j].Signature {
			return records[i].Signature < records[j].Signature
		}
		if records[i].Name != records[j].Name {
			return records[i].Name < records[j].Name
		}
		if records[i].Kind != records[j].Kind {
			return records[i].Kind < records[j].Kind
		}
		return records[i].Site < records[j].Site
	})
}

func SortCollisions(collisions []Collision) {
	sort.SliceStable(collisions, func(i, j int) bool {
		if collisions[i].Size != collisions[j].Size {
			return collisions[i].Size < collisions[j].Size
		}
		return collisions[i].Signature < collisions[j].Signature
	})
	for idx := range collisions {
		sort.Strings(collisions[idx].Types)
	}
}

func Collisions(records []Record) []Collision {
	type key struct {
		size      uint32
		signature string
	}
	groups := make(map[key]map[string]struct{})
	for _, rec := range records {
		if rec.Signature == "" || rec.Name == "" {
			continue
		}
		k := key{size: rec.Size, signature: rec.Signature}
		if groups[k] == nil {
			groups[k] = make(map[string]struct{})
		}
		groups[k][rec.Name] = struct{}{}
	}

	collisions := make([]Collision, 0, len(groups))
	for k, names := range groups {
		if len(names) < 2 {
			continue
		}
		types := make([]string, 0, len(names))
		for name := range names {
			types = append(types, name)
		}
		collisions = append(collisions, Collision{
			Size:      k.size,
			Signature: k.signature,
			Types:     types,
		})
	}
	SortCollisions(collisions)
	return collisions
}

func (r Record) AppendJSON(dst []byte) []byte {
	dst = append(dst, `{"kind":`...)
	dst = appendJSONString(dst, r.Kind)
	dst = append(dst, `,"name":`...)
	dst = appendJSONString(dst, r.Name)
	dst = append(dst, `,"signature":`...)
	dst = appendJSONString(dst, r.Signature)
	dst = append(dst, `,"size":`...)
	dst = strconv.AppendUint(dst, uint64(r.Size), 10)
	dst = append(dst, `,"flags":`...)
	dst = appendJSONString(dst, hex32(r.Flags))
	dst = append(dst, `,"flags_decoded":`...)
	dst = appendStringArray(dst, r.FlagsDecoded)
	dst = append(dst, `,"site":`...)
	dst = appendJSONString(dst, hex64(r.Site))
	if r.Kind == KindVar {
		dst = append(dst, `,"hdr_signature":`...)
		dst = appendJSONString(dst, r.HdrSignature)
		dst = append(dst, `,"elem_signature":`...)
		dst = appendJSONString(dst, r.ElemSignature)
	}
	dst = append(dst, '}')
	return dst
}

func (c Collision) AppendJSON(dst []byte) []byte {
	dst = append(dst, `{"kind":`...)
	dst = appendJSONString(dst, KindCollision)
	dst = append(dst, `,"size":`...)
	dst = strconv.AppendUint(dst, uint64(c.Size), 10)
	dst = append(dst, `,"signature":`...)
	dst = appendJSONString(dst, c.Signature)
	dst = append(dst, `,"types":`...)
	dst = appendStringArray(dst, c.Types)
	dst = append(dst, '}')
	return dst
}

func appendStringArray(dst []byte, values []string) []byte {
	dst = append(dst, '[')
	for idx, value := range values {
		if idx > 0 {
			dst = append(dst, ',')
		}
		dst = appendJSONString(dst, value)
	}
	dst = append(dst, ']')
	return dst
}

func appendJSONString(dst []byte, value string) []byte {
	return strconv.AppendQuote(dst, strings.ToValidUTF8(value, "\uFFFD"))
}

func hex32(value uint32) string {
	return "0x" + strconv.FormatUint(uint64(value), 16)
}

func hex64(value uint64) string {
	return "0x" + strconv.FormatUint(value, 16)
}

func DecodeFlags(flags uint32) []string {
	out := make([]string, 0, len(flagDefs)+1)
	for _, def := range flagDefs {
		if flags&def.value != 0 {
			out = append(out, def.name)
		}
	}
	if flags&0xffff0000 != 0 {
		out = append(out, "HASH")
	}
	return out
}
