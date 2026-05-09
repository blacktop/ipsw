package xrefs

import (
	"io"
	"sort"
	"strconv"
	"strings"
)

type Record struct {
	Source       string
	Image        string
	CallerSymbol string
	Callsite     string
	CheckFn      string
	Key          string
	Value        string
	Resolved     bool
	Extra        map[string]string
}

func SortRecords(records []Record) {
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].Source != records[j].Source {
			return records[i].Source < records[j].Source
		}
		if records[i].Image != records[j].Image {
			return records[i].Image < records[j].Image
		}
		if records[i].Callsite != records[j].Callsite {
			return callsiteLess(records[i].Callsite, records[j].Callsite)
		}
		if records[i].CheckFn != records[j].CheckFn {
			return records[i].CheckFn < records[j].CheckFn
		}
		if records[i].Key != records[j].Key {
			return records[i].Key < records[j].Key
		}
		return records[i].Value < records[j].Value
	})
}

func callsiteLess(a, b string) bool {
	aa, aerr := strconv.ParseUint(strings.TrimPrefix(a, "0x"), 16, 64)
	bb, berr := strconv.ParseUint(strings.TrimPrefix(b, "0x"), 16, 64)
	if aerr == nil && berr == nil {
		return aa < bb
	}
	return a < b
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

func (r Record) AppendJSON(dst []byte) []byte {
	dst = append(dst, `{"callsite":`...)
	dst = strconv.AppendQuote(dst, r.Callsite)
	dst = append(dst, `,"caller_symbol":`...)
	dst = strconv.AppendQuote(dst, r.CallerSymbol)
	dst = append(dst, `,"check_fn":`...)
	dst = strconv.AppendQuote(dst, r.CheckFn)
	dst = append(dst, `,"extra":`...)
	dst = appendExtra(dst, r.Extra)
	dst = append(dst, `,"image":`...)
	dst = strconv.AppendQuote(dst, r.Image)
	dst = append(dst, `,"key":`...)
	dst = strconv.AppendQuote(dst, r.Key)
	dst = append(dst, `,"resolved":`...)
	dst = strconv.AppendBool(dst, r.Resolved)
	dst = append(dst, `,"source":`...)
	dst = strconv.AppendQuote(dst, r.Source)
	dst = append(dst, `,"value":`...)
	dst = strconv.AppendQuote(dst, r.Value)
	dst = append(dst, '}')
	return dst
}

func appendExtra(dst []byte, extra map[string]string) []byte {
	if len(extra) == 0 {
		return append(dst, "{}"...)
	}
	dst = append(dst, `{"slice_notes":`...)
	dst = strconv.AppendQuote(dst, extra["slice_notes"])
	dst = append(dst, '}')
	return dst
}
