package nsxpc

import (
	"io"
	"sort"
	"strconv"
	"strings"
)

const (
	KindInterface          = "interface"
	KindInterfaceClasses   = "interface_classes"
	KindProtocolMethod     = "protocol_method"
	KindSecureCodingDecode = "secure_coding_decode"
)

type Record struct {
	Kind           string
	Image          string
	Callsite       string
	Protocol       string
	Class          string
	Selector       string
	ArgIndex       int
	OfReply        bool
	Classes        []string
	Required       bool
	Instance       bool
	TypeEncoding   string
	ParamClasses   []string
	ReturnClass    string
	DecodedClasses []string
	Key            string
	Resolved       bool
	Extra          map[string]string
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

func SortRecords(records []Record) {
	for idx := range records {
		records[idx].Classes = sortedStrings(records[idx].Classes)
		records[idx].ParamClasses = append([]string(nil), records[idx].ParamClasses...)
		records[idx].DecodedClasses = sortedStrings(records[idx].DecodedClasses)
		if records[idx].Extra == nil {
			records[idx].Extra = map[string]string{}
		}
	}
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].Kind != records[j].Kind {
			return records[i].Kind < records[j].Kind
		}
		if records[i].Image != records[j].Image {
			return records[i].Image < records[j].Image
		}
		if records[i].Protocol != records[j].Protocol {
			return records[i].Protocol < records[j].Protocol
		}
		if records[i].Class != records[j].Class {
			return records[i].Class < records[j].Class
		}
		if records[i].Callsite != records[j].Callsite {
			return callsiteLess(records[i].Callsite, records[j].Callsite)
		}
		if records[i].Selector != records[j].Selector {
			return records[i].Selector < records[j].Selector
		}
		return records[i].TypeEncoding < records[j].TypeEncoding
	})
}

func (r Record) AppendJSON(dst []byte) []byte {
	switch r.Kind {
	case KindInterface:
		dst = appendCommonPrefix(dst, r)
		dst = append(dst, `,"kind":`...)
		dst = strconv.AppendQuote(dst, r.Kind)
		dst = append(dst, `,"protocol":`...)
		dst = strconv.AppendQuote(dst, r.Protocol)
		dst = appendResolvedSuffix(dst, r)
	case KindInterfaceClasses:
		dst = append(dst, `{"arg_index":`...)
		dst = strconv.AppendInt(dst, int64(r.ArgIndex), 10)
		dst = append(dst, `,"callsite":`...)
		dst = strconv.AppendQuote(dst, r.Callsite)
		dst = append(dst, `,"classes":`...)
		dst = appendStringArray(dst, r.Classes)
		dst = append(dst, `,"extra":`...)
		dst = appendExtra(dst, r.Extra)
		dst = append(dst, `,"image":`...)
		dst = strconv.AppendQuote(dst, r.Image)
		dst = append(dst, `,"kind":`...)
		dst = strconv.AppendQuote(dst, r.Kind)
		dst = append(dst, `,"of_reply":`...)
		dst = strconv.AppendBool(dst, r.OfReply)
		dst = append(dst, `,"protocol":`...)
		dst = strconv.AppendQuote(dst, r.Protocol)
		dst = append(dst, `,"resolved":`...)
		dst = strconv.AppendBool(dst, r.Resolved)
		dst = append(dst, `,"selector":`...)
		dst = strconv.AppendQuote(dst, r.Selector)
		dst = append(dst, '}')
	case KindProtocolMethod:
		dst = appendCommonPrefix(dst, r)
		dst = append(dst, `,"instance":`...)
		dst = strconv.AppendBool(dst, r.Instance)
		dst = append(dst, `,"kind":`...)
		dst = strconv.AppendQuote(dst, r.Kind)
		dst = append(dst, `,"param_classes":`...)
		dst = appendStringArray(dst, r.ParamClasses)
		dst = append(dst, `,"protocol":`...)
		dst = strconv.AppendQuote(dst, r.Protocol)
		dst = append(dst, `,"required":`...)
		dst = strconv.AppendBool(dst, r.Required)
		dst = append(dst, `,"resolved":`...)
		dst = strconv.AppendBool(dst, r.Resolved)
		dst = append(dst, `,"return_class":`...)
		dst = strconv.AppendQuote(dst, r.ReturnClass)
		dst = append(dst, `,"selector":`...)
		dst = strconv.AppendQuote(dst, r.Selector)
		dst = append(dst, `,"type_encoding":`...)
		dst = strconv.AppendQuote(dst, r.TypeEncoding)
		dst = append(dst, '}')
	case KindSecureCodingDecode:
		dst = append(dst, `{"callsite":`...)
		dst = strconv.AppendQuote(dst, r.Callsite)
		dst = append(dst, `,"class":`...)
		dst = strconv.AppendQuote(dst, r.Class)
		dst = append(dst, `,"decoded_classes":`...)
		dst = appendStringArray(dst, r.DecodedClasses)
		dst = append(dst, `,"extra":`...)
		dst = appendExtra(dst, r.Extra)
		dst = append(dst, `,"image":`...)
		dst = strconv.AppendQuote(dst, r.Image)
		dst = append(dst, `,"key":`...)
		dst = strconv.AppendQuote(dst, r.Key)
		dst = append(dst, `,"kind":`...)
		dst = strconv.AppendQuote(dst, r.Kind)
		dst = append(dst, `,"resolved":`...)
		dst = strconv.AppendBool(dst, r.Resolved)
		dst = append(dst, '}')
	default:
		dst = appendCommonPrefix(dst, r)
		dst = append(dst, `,"kind":`...)
		dst = strconv.AppendQuote(dst, r.Kind)
		dst = appendResolvedSuffix(dst, r)
	}
	return dst
}

func appendCommonPrefix(dst []byte, r Record) []byte {
	dst = append(dst, `{"callsite":`...)
	dst = strconv.AppendQuote(dst, r.Callsite)
	dst = append(dst, `,"extra":`...)
	dst = appendExtra(dst, r.Extra)
	dst = append(dst, `,"image":`...)
	dst = strconv.AppendQuote(dst, r.Image)
	return dst
}

func appendResolvedSuffix(dst []byte, r Record) []byte {
	dst = append(dst, `,"resolved":`...)
	dst = strconv.AppendBool(dst, r.Resolved)
	dst = append(dst, '}')
	return dst
}

func appendExtra(dst []byte, extra map[string]string) []byte {
	if len(extra) == 0 || extra["slice_notes"] == "" {
		return append(dst, "{}"...)
	}
	dst = append(dst, `{"slice_notes":`...)
	dst = strconv.AppendQuote(dst, extra["slice_notes"])
	dst = append(dst, '}')
	return dst
}

func appendStringArray(dst []byte, items []string) []byte {
	dst = append(dst, '[')
	for idx, item := range items {
		if idx > 0 {
			dst = append(dst, ',')
		}
		dst = strconv.AppendQuote(dst, item)
	}
	dst = append(dst, ']')
	return dst
}

func sortedStrings(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	out := append([]string(nil), items...)
	sort.Strings(out)
	return slicesCompact(out)
}

func slicesCompact(items []string) []string {
	if len(items) < 2 {
		return items
	}
	write := 1
	for read := 1; read < len(items); read++ {
		if items[read] == items[write-1] {
			continue
		}
		items[write] = items[read]
		write++
	}
	return items[:write]
}

func callsiteLess(a, b string) bool {
	aa, aerr := strconv.ParseUint(strings.TrimPrefix(a, "0x"), 16, 64)
	bb, berr := strconv.ParseUint(strings.TrimPrefix(b, "0x"), 16, 64)
	if aerr == nil && berr == nil {
		return aa < bb
	}
	return a < b
}
