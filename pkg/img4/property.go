package img4

import (
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"
	"time"
	"unicode"

	"github.com/blacktop/ipsw/internal/utils"
)

// Property represents a dynamic IMG4 property with auto-detected type
type Property struct {
	Name  string // 4-character property name (CHIP, BORD, etc.)
	Value any    // int, bool, string, or []byte based on ASN.1 type detection
}

// ParsePropertySet parses a SET of properties dynamically into []Property format
// Used by both manifest MANP and image descriptors
func ParsePropertySet(data []byte) ([]Property, error) {
	var properties []Property

	// Parse the SET of property entries - these are raw private tag entries
	remaining := data
	for len(remaining) > 0 {
		var entry asn1.RawValue
		rest, err := asn1.Unmarshal(remaining, &entry)
		if err != nil {
			break // No more entries to parse
		}

		// Only process private class entries (class 3)
		if entry.Class != 3 {
			remaining = rest
			continue
		}

		// Parse the property entry which contains a SEQUENCE with name and value
		var prop struct {
			Name  string
			Value asn1.RawValue
		}

		if _, err := asn1.Unmarshal(entry.Bytes, &prop); err != nil {
			remaining = rest
			continue // Skip malformed properties
		}

		// Detect and parse the value based on its ASN.1 type and known property types
		value := ParsePropertyValueWithTag(prop.Value, entry.Tag)
		if value != nil {
			properties = append(properties, Property{
				Name:  prop.Name,
				Value: value,
			})
		}

		remaining = rest
	}

	return properties, nil
}

// ParsePropertyMap parses ASN.1 property data into a map[string]any format
// Used by restore info for direct property access
func ParsePropertyMap(data []byte) (map[string]any, error) {
	properties := make(map[string]any)

	remaining := data
	for len(remaining) > 0 {
		var entry asn1.RawValue
		rest, err := asn1.Unmarshal(remaining, &entry)
		if err != nil {
			break // No more entries
		}

		// Only process private class entries (class 3)
		if entry.Class != 3 {
			remaining = rest
			continue
		}

		// Parse property (SEQUENCE with name and value)
		var prop struct {
			Name  string
			Value asn1.RawValue
		}

		if _, err := asn1.Unmarshal(entry.Bytes, &prop); err != nil {
			remaining = rest
			continue
		}

		if value := ParsePropertyValueWithTag(prop.Value, entry.Tag); value != nil {
			properties[prop.Name] = value
		}

		remaining = rest
	}

	return properties, nil
}

// ParsePropertyValueWithTag dynamically detects and parses property values based on ASN.1 type and known tag
func ParsePropertyValueWithTag(rawValue asn1.RawValue, tag int) any {
	switch rawValue.Tag {
	case asn1.TagInteger:
		// Try parsing as int64 first
		var intVal int64
		if _, err := asn1.Unmarshal(rawValue.FullBytes, &intVal); err == nil {
			// Check if this should be parsed as a timestamp
			if getPropertyType(tag) == PropTypeTimestamp {
				return time.Unix(intVal, 0).UTC()
			}

			// Special handling for boot nonce - keep as int64
			if tag == tagBNCN {
				return intVal
			}

			// Check if it fits in int
			if intVal >= int64(^uint(0)>>1) || intVal <= -int64(^uint(0)>>1)-1 {
				return intVal
			}
			return int(intVal)
		}

		// If that fails, try parsing as big.Int for large values
		if len(rawValue.Bytes) > 0 {
			bigVal := new(big.Int)
			bigVal.SetBytes(rawValue.Bytes)
			if bigVal.IsUint64() {
				return bigVal.Uint64()
			}
			return bigVal.String()
		}
		return nil

	case asn1.TagBoolean:
		var boolVal bool
		if _, err := asn1.Unmarshal(rawValue.FullBytes, &boolVal); err == nil {
			return boolVal
		}
		return nil

	case asn1.TagOctetString:
		// Use property type lookup to determine if this should be a string or binary data
		propType := getPropertyType(tag)
		switch propType {
		case PropTypeString:
			return string(rawValue.Bytes)
		case PropTypeHash:
			return rawValue.Bytes
		case PropTypeAuto:
			// Auto-detect using printable string detection for unknown properties
			if len(rawValue.Bytes) > 0 && isPrintableString(string(rawValue.Bytes)) {
				return string(rawValue.Bytes)
			}
			return rawValue.Bytes
		default:
			return rawValue.Bytes
		}

	case asn1.TagIA5String, asn1.TagUTF8String, asn1.TagPrintableString:
		return string(rawValue.Bytes)

	default:
		// For unknown types, store as raw bytes
		return rawValue.Bytes
	}
}

// FormatPropertyValue formats property values for display
func FormatPropertyValue(value any) string {
	switch v := value.(type) {
	case []byte:
		if len(v) > 100 {
			return "\n" + strings.TrimSpace(utils.HexDump(v, 0))
		}
		return fmt.Sprintf("%x", v)
	case string:
		if len(v) > 32 {
			return fmt.Sprintf("%.32s...", v)
		}
		return v
	case time.Time:
		return fmt.Sprintf("%s (%d)", v.Format("2006-01-02 15:04:05 UTC"), v.Unix())
	default:
		return fmt.Sprintf("%v", v)
	}
}

// ConvertPropertySliceToMap converts []Property format to map[string]any format
func ConvertPropertySliceToMap(props []Property) map[string]any {
	result := make(map[string]any)
	for _, prop := range props {
		result[prop.Name] = prop.Value
	}
	return result
}

// ConvertPropertyMapToSlice converts map[string]any format to []Property format
func ConvertPropertyMapToSlice(props map[string]any) []Property {
	var result []Property
	for name, value := range props {
		result = append(result, Property{
			Name:  name,
			Value: value,
		})
	}
	return result
}

// isPrintableString checks if a string contains only printable characters
func isPrintableString(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) && !unicode.IsSpace(r) {
			return false
		}
	}
	return true
}
