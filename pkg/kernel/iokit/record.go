package iokit

import (
	"io"
	"sort"
	"strconv"
)

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
		if records[idx].Extra == nil {
			records[idx].Extra = map[string]string{}
		}
	}
	sort.SliceStable(records, func(i, j int) bool {
		ib, ic := sortBundleClass(records[i])
		jb, jc := sortBundleClass(records[j])
		if records[i].Kind != records[j].Kind {
			return records[i].Kind < records[j].Kind
		}
		if ib != jb {
			return ib < jb
		}
		if ic != jc {
			return ic < jc
		}
		if records[i].Selector != records[j].Selector {
			return records[i].Selector < records[j].Selector
		}
		if records[i].MethodAddr != records[j].MethodAddr {
			return records[i].MethodAddr < records[j].MethodAddr
		}
		if records[i].UserClientClass != records[j].UserClientClass {
			return records[i].UserClientClass < records[j].UserClientClass
		}
		return extraSortString(records[i].Extra) < extraSortString(records[j].Extra)
	})
}

func sortBundleClass(r Record) (string, string) {
	if r.Kind == KindServiceClient {
		return r.ServiceBundle, r.ServiceClass
	}
	return r.Bundle, r.Class
}

func (r Record) AppendJSON(dst []byte) []byte {
	switch r.Kind {
	case KindMethod:
		dst = append(dst, `{"bundle":`...)
		dst = strconv.AppendQuote(dst, r.Bundle)
		dst = append(dst, `,"class":`...)
		dst = strconv.AppendQuote(dst, r.Class)
		dst = append(dst, `,"dispatch_kind":`...)
		dst = strconv.AppendQuote(dst, r.DispatchKind)
		dst = append(dst, `,"extra":`...)
		dst = appendExtra(dst, r.Extra)
		dst = append(dst, `,"flags":`...)
		dst = strconv.AppendInt(dst, r.Flags, 10)
		dst = append(dst, `,"kind":`...)
		dst = strconv.AppendQuote(dst, r.Kind)
		dst = append(dst, `,"method_addr":`...)
		dst = strconv.AppendQuote(dst, r.MethodAddr)
		dst = append(dst, `,"method_symbol":`...)
		dst = strconv.AppendQuote(dst, r.MethodSymbol)
		dst = append(dst, `,"resolved":`...)
		dst = strconv.AppendBool(dst, r.Resolved)
		dst = append(dst, `,"scalar_input_count":`...)
		dst = strconv.AppendInt(dst, r.ScalarInputCount, 10)
		dst = append(dst, `,"scalar_output_count":`...)
		dst = strconv.AppendInt(dst, r.ScalarOutputCount, 10)
		dst = append(dst, `,"selector":`...)
		dst = strconv.AppendInt(dst, int64(r.Selector), 10)
		dst = append(dst, `,"struct_input_size":`...)
		dst = strconv.AppendInt(dst, r.StructInputSize, 10)
		dst = append(dst, `,"struct_output_size":`...)
		dst = strconv.AppendInt(dst, r.StructOutputSize, 10)
		dst = append(dst, '}')
	case KindServiceClient:
		dst = append(dst, `{"extra":`...)
		dst = appendExtra(dst, r.Extra)
		dst = append(dst, `,"kind":`...)
		dst = strconv.AppendQuote(dst, r.Kind)
		dst = append(dst, `,"resolved":`...)
		dst = strconv.AppendBool(dst, r.Resolved)
		dst = append(dst, `,"service_bundle":`...)
		dst = strconv.AppendQuote(dst, r.ServiceBundle)
		dst = append(dst, `,"service_class":`...)
		dst = strconv.AppendQuote(dst, r.ServiceClass)
		dst = append(dst, `,"source":`...)
		dst = strconv.AppendQuote(dst, r.Source)
		dst = append(dst, `,"user_client_bundle":`...)
		dst = strconv.AppendQuote(dst, r.UserClientBundle)
		dst = append(dst, `,"user_client_class":`...)
		dst = strconv.AppendQuote(dst, r.UserClientClass)
		dst = append(dst, '}')
	default:
		dst = append(dst, `{"extra":`...)
		dst = appendExtra(dst, r.Extra)
		dst = append(dst, `,"kind":`...)
		dst = strconv.AppendQuote(dst, r.Kind)
		dst = append(dst, '}')
	}
	return dst
}

func appendExtra(dst []byte, extra map[string]string) []byte {
	keys := sortedExtraKeys(extra)
	if len(keys) == 0 {
		return append(dst, "{}"...)
	}
	dst = append(dst, '{')
	for idx, key := range keys {
		if idx > 0 {
			dst = append(dst, ',')
		}
		dst = strconv.AppendQuote(dst, key)
		dst = append(dst, ':')
		dst = strconv.AppendQuote(dst, extra[key])
	}
	dst = append(dst, '}')
	return dst
}

func extraSortString(extra map[string]string) string {
	keys := sortedExtraKeys(extra)
	if len(keys) == 0 {
		return ""
	}
	var out []byte
	for _, key := range keys {
		out = strconv.AppendQuote(out, key)
		out = append(out, '=')
		out = strconv.AppendQuote(out, extra[key])
		out = append(out, ';')
	}
	return string(out)
}

func sortedExtraKeys(extra map[string]string) []string {
	keys := make([]string, 0, len(extra))
	for key, value := range extra {
		if value != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}
