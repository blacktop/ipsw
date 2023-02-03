package entitlements

import (
	"bytes"
	"encoding/asn1"
	"fmt"

	"github.com/blacktop/go-plist"
)

type item struct {
	Key string `asn1:"utf8"`
	Val any
}

type boolItem struct {
	Key string `asn1:"utf8"`
	Val bool
}

type stringItem struct {
	Key string `asn1:"utf8"`
	Val string `asn1:"utf8"`
}

type stringSliceItem struct {
	Key string   `asn1:"utf8"`
	Val []string `asn1:"set,tag:12"`
}

func DerEncode(input []byte) ([]byte, error) {
	var entitlements map[string]any

	if err := plist.NewDecoder(bytes.NewReader(input)).Decode(&entitlements); err != nil {
		return nil, fmt.Errorf("failed to decode entitlements plist: %w", err)
	}

	var items []any
	for k, v := range entitlements {
		switch t := v.(type) {
		case bool:
			items = append(items, boolItem{k, t})
		case string:
			items = append(items, stringItem{k, t})
		case []any:
			var stringSlice []string
			for _, s := range t {
				stringSlice = append(stringSlice, s.(string))
			}
			items = append(items, stringSliceItem{k, stringSlice})
		default:
			items = append(items, item{k, v})
		}
	}

	return asn1.MarshalWithParams(items, "set")
}
