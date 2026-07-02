package iokit

import (
	"fmt"
	"strconv"

	"github.com/blacktop/ipsw/pkg/kernelcache/cpp"
)

func annotateExternalMethodVtableRecords(records []Record, entry cpp.VtableEntry) {
	for idx := range records {
		annotateExternalMethodVtable(&records[idx], entry)
	}
}

func annotateExternalMethodVtable(rec *Record, entry cpp.VtableEntry) {
	if rec == nil {
		return
	}
	if rec.Extra == nil {
		rec.Extra = map[string]string{}
	}
	rec.Extra["external_method_slot"] = strconv.Itoa(entry.Index)
	rec.Extra["external_method_slot_addr"] = hexAddr(entry.SlotAddress)
	rec.Extra["external_method_offset"] = hexAddr(entry.Offset)
	rec.Extra["external_method_auth"] = strconv.FormatBool(entry.Auth)
	rec.Extra["external_method_pure_virtual"] = strconv.FormatBool(entry.PureVirtual)
	if entry.Auth {
		rec.Extra["external_method_pac"] = fmt.Sprintf("0x%04x", entry.PAC)
		rec.Extra["external_method_key"] = pacKeyName(entry.Key)
		rec.Extra["external_method_addr_div"] = strconv.FormatBool(entry.AddrDiv)
	}
	if entry.Class != "" {
		rec.Extra["external_method_class"] = entry.Class
	}
	if entry.Method != "" {
		rec.Extra["external_method_name"] = entry.Method
	}
	if entry.Mangled != "" {
		rec.Extra["external_method_mangled"] = entry.Mangled
	}
}

func pacKeyName(key uint8) string {
	switch key {
	case 0:
		return "IA"
	case 1:
		return "IB"
	case 2:
		return "DA"
	case 3:
		return "DB"
	default:
		return strconv.Itoa(int(key))
	}
}
