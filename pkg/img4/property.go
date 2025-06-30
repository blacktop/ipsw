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
	return ParsePropertiesAs[[]Property](data)
}

// ParsePropertyMap parses ASN.1 property data into a map[string]any format
// Used by restore info for direct property access
func ParsePropertyMap(data []byte) (map[string]any, error) {
	return ParsePropertiesAs[map[string]any](data)
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
			if intVal > int64(^uint(0)>>1) || intVal < -int64(^uint(0)>>1)-1 {
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

// PropertiesSliceToMap converts []Property to map[string]any
func PropertiesSliceToMap(props []Property) map[string]any {
	result := make(map[string]any, len(props))
	for _, prop := range props {
		result[prop.Name] = prop.Value
	}
	return result
}

// PropertiesMapToSlice converts map[string]any to []Property
func PropertiesMapToSlice(props map[string]any) []Property {
	result := make([]Property, 0, len(props))
	for name, value := range props {
		result = append(result, Property{
			Name:  name,
			Value: value,
		})
	}
	return result
}

// PropertyMarshalFormat specifies the ASN.1 structure format for property marshaling
type PropertyMarshalFormat int

const (
	// RestoreInfoFormat - used by IM4R, has SEQUENCE with name and value
	RestoreInfoFormat PropertyMarshalFormat = iota
	// ManifestFormat - used by IM4M, has SEQUENCE with name and SET containing value
	ManifestFormat
)

// MarshalProperties marshals properties to ASN.1 format
// Supports both RestoreInfo format (SEQUENCE with name+value) and Manifest format (SEQUENCE with name+SET)
func MarshalProperties(props map[string]any, format PropertyMarshalFormat) ([]byte, error) {
	var entries []asn1.RawValue

	for name, value := range props {
		entry, err := marshalSingleProperty(name, value, format)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal property %s: %v", name, err)
		}
		entries = append(entries, entry)
	}

	// Concatenate all entries directly (no outer wrapper)
	var result []byte
	for _, entry := range entries {
		entryBytes, err := asn1.Marshal(entry)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal property entry: %v", err)
		}
		result = append(result, entryBytes...)
	}
	return result, nil
}

// MarshalPropertiesSlice marshals []Property format to ASN.1 RawValues
func MarshalPropertiesSlice(props []Property, format PropertyMarshalFormat) ([]asn1.RawValue, error) {
	var entries []asn1.RawValue

	for _, prop := range props {
		entry, err := marshalSingleProperty(prop.Name, prop.Value, format)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal property %s: %v", prop.Name, err)
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

// marshalSingleProperty marshals a single property name/value pair to ASN.1 format
func marshalSingleProperty(name string, value any, format PropertyMarshalFormat) (asn1.RawValue, error) {
	// First, marshal the value itself
	var valueBytes []byte
	var tag int
	var err error

	switch v := value.(type) {
	case int:
		valueBytes, err = asn1.Marshal(v)
		tag = asn1.TagInteger
	case int64:
		valueBytes, err = asn1.Marshal(v)
		tag = asn1.TagInteger
	case uint64:
		valueBytes, err = asn1.Marshal(new(big.Int).SetUint64(v))
		tag = asn1.TagInteger
	case bool:
		valueBytes, err = asn1.Marshal(v)
		tag = asn1.TagBoolean
	case string:
		valueBytes, err = asn1.Marshal(v)
		tag = asn1.TagIA5String
	case []byte:
		valueBytes, err = asn1.Marshal(v)
		tag = asn1.TagOctetString
	case time.Time:
		valueBytes, err = asn1.Marshal(v.Unix())
		tag = asn1.TagInteger
	default:
		return asn1.RawValue{}, fmt.Errorf("unsupported property type: %T", v)
	}

	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("failed to marshal value: %v", err)
	}

	// Create the property structure based on format
	var propBytes []byte
	switch format {
	case RestoreInfoFormat:
		// RestoreInfo format: SEQUENCE with name and value
		propStruct := struct {
			Name  string
			Value asn1.RawValue
		}{
			Name: name,
			Value: asn1.RawValue{
				Tag:       tag,
				FullBytes: valueBytes,
			},
		}
		propBytes, err = asn1.Marshal(propStruct)

	case ManifestFormat:
		// Manifest format: SEQUENCE with name and SET containing value
		propStruct := struct {
			Name  string
			Value asn1.RawValue `asn1:"set"`
		}{
			Name: name,
			Value: asn1.RawValue{
				Tag:        asn1.TagSet,
				IsCompound: true,
				Bytes:      valueBytes,
			},
		}
		propBytes, err = asn1.Marshal(propStruct)

	default:
		return asn1.RawValue{}, fmt.Errorf("unsupported marshal format: %v", format)
	}

	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("failed to marshal property structure: %v", err)
	}

	// Return the private class entry
	return asn1.RawValue{
		Class:      asn1.ClassPrivate,
		Tag:        fourCCtoInt(name),
		IsCompound: true,
		Bytes:      propBytes,
	}, nil
}

// ParsePropertiesAs parses properties from ASN.1 data and returns the specified type
func ParsePropertiesAs[T []Property | map[string]any](data []byte) (T, error) {
	var zero T
	remaining := data

	// Determine return type and initialize accordingly
	var properties []Property
	var propertyMap map[string]any
	var returnSlice bool

	switch any(zero).(type) {
	case []Property:
		returnSlice = true
	case map[string]any:
		propertyMap = make(map[string]any)
	default:
		return zero, fmt.Errorf("unsupported return type")
	}

	for len(remaining) > 0 {
		var entry asn1.RawValue
		rest, err := asn1.Unmarshal(remaining, &entry)
		if err != nil {
			break // No more entries
		}

		// Only process private class entries (class 3)
		if entry.Class != asn1.ClassPrivate {
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

		value := ParsePropertyValueWithTag(prop.Value, entry.Tag)
		if value != nil {
			if returnSlice {
				properties = append(properties, Property{
					Name:  prop.Name,
					Value: value,
				})
			} else {
				propertyMap[prop.Name] = value
			}
		}

		remaining = rest
	}

	if returnSlice {
		return any(properties).(T), nil
	}
	return any(propertyMap).(T), nil
}

// fourCCtoInt converts a 4-character string to an integer
func fourCCtoInt(fourCC string) int {
	if len(fourCC) != 4 {
		// Return an error value that can be detected rather than masking errors with zero
		return -1
	}
	return int(fourCC[0])<<24 | int(fourCC[1])<<16 | int(fourCC[2])<<8 | int(fourCC[3])
}

// propertyTypeMap provides a centralized lookup for property types based on their ASN.1 tags
var propertyTypeMap = map[int]PropType{
	// String properties (stored as OCTET STRING but should be displayed as text)
	fourCCtoInt("love"): PropTypeString, // love - Version string
	fourCCtoInt("prtp"): PropTypeString, // prtp - Platform type
	fourCCtoInt("sdkp"): PropTypeString, // sdkp - SDK platform
	fourCCtoInt("tagt"): PropTypeString, // tagt - Target tag
	fourCCtoInt("tatp"): PropTypeString, // tatp - Target platform
	fourCCtoInt("pave"): PropTypeString, // pave - Platform version
	fourCCtoInt("vnum"): PropTypeString, // vnum - Version number
	fourCCtoInt("apmv"): PropTypeString, // apmv - Apple PMU version

	// Hash/binary properties (stored as OCTET STRING, display as hex)
	fourCCtoInt("srvn"): PropTypeHash, // srvn - Security revision number
	fourCCtoInt("snon"): PropTypeHash, // snon - Security nonce
	fourCCtoInt("BNCH"): PropTypeHash, // BNCH - Boot nonce hash
	fourCCtoInt("DGST"): PropTypeHash, // DGST - Digest (hash value)
	fourCCtoInt("tbmr"): PropTypeHash, // tbmr - Trusted boot measurement register
	fourCCtoInt("tbms"): PropTypeHash, // tbms - Trusted boot measurement signature
	fourCCtoInt("mmap"): PropTypeHash, // mmap - Memory map
	fourCCtoInt("rddg"): PropTypeHash, // rddg - RD Debug

	// Boolean properties
	fourCCtoInt("CPRO"): PropTypeBool, // CPRO - Certificate production status
	fourCCtoInt("CSEC"): PropTypeBool, // CSEC - Certificate security mode
	fourCCtoInt("EKEY"): PropTypeBool, // EKEY - Encryption key required
	fourCCtoInt("EPRO"): PropTypeBool, // EPRO - Encryption production
	fourCCtoInt("ESEC"): PropTypeBool, // ESEC - Encryption security

	// Timestamp properties (stored as INTEGER, display as time)
	fourCCtoInt("tstp"): PropTypeTimestamp, // tstp - Timestamp

	// Integer properties
	fourCCtoInt("BORD"): PropTypeInt,  // BORD - Board ID
	fourCCtoInt("CEPO"): PropTypeInt,  // CEPO - Certificate epoch
	fourCCtoInt("CHIP"): PropTypeInt,  // CHIP - Chip ID
	fourCCtoInt("ECID"): PropTypeInt,  // ECID - Exclusive chip identifier
	fourCCtoInt("SDOM"): PropTypeInt,  // SDOM - Security domain
	fourCCtoInt("augs"): PropTypeInt,  // augs - Augmented security
	fourCCtoInt("clas"): PropTypeInt,  // clas - Device class
	fourCCtoInt("fchp"): PropTypeInt,  // fchp - Firmware chip
	fourCCtoInt("styp"): PropTypeInt,  // styp - Security type
	fourCCtoInt("type"): PropTypeInt,  // type - Type
	fourCCtoInt("impl"): PropTypeInt,  // impl - Implementation
	fourCCtoInt("iocv"): PropTypeInt,  // iocv - IO coprocessor version
	fourCCtoInt("arms"): PropTypeInt,  // arms - ARM security
	fourCCtoInt("ar1s"): PropTypeInt,  // ar1s - ARM1 security
	fourCCtoInt("cons"): PropTypeHash, // cons - Console (binary data)
	fourCCtoInt("drmc"): PropTypeHash, // drmc - DRMC (binary data)
	fourCCtoInt("tz0s"): PropTypeInt,  // tz0s - TrustZone 0 security
	fourCCtoInt("tz1s"): PropTypeInt,  // tz1s - TrustZone 1 security
	fourCCtoInt("kcbf"): PropTypeInt,  // kcbf - Kernel cache B offset (TXM)
	fourCCtoInt("kcbz"): PropTypeInt,  // kcbz - Kernel cache B size (TXM)
	fourCCtoInt("kcep"): PropTypeInt,  // kcep - Kernel cache epoch
	fourCCtoInt("kclf"): PropTypeInt,  // kclf - Kernel cache L offset
	fourCCtoInt("kclo"): PropTypeInt,  // kclo - Kernel cache L origin
	fourCCtoInt("kclz"): PropTypeInt,  // kclz - Kernel cache L size
	fourCCtoInt("kcmf"): PropTypeInt,  // kcmf - Kernel cache M offset (SPTM)
	fourCCtoInt("kcmz"): PropTypeInt,  // kcmz - Kernel cache M size (SPTM)
	fourCCtoInt("kcrf"): PropTypeInt,  // kcrf - Kernel cache R offset
	fourCCtoInt("kcrz"): PropTypeInt,  // kcrz - Kernel cache R size
	fourCCtoInt("kcsz"): PropTypeInt,  // kcsz - Kernel cache S size
	fourCCtoInt("kcwf"): PropTypeInt,  // kcwf - Kernel cache W offset
	fourCCtoInt("kcwz"): PropTypeInt,  // kcwz - Kernel cache W size
	fourCCtoInt("kcxf"): PropTypeInt,  // kcxf - Kernel cache X offset
	fourCCtoInt("kcxz"): PropTypeInt,  // kcxz - Kernel cache X size
}

// PropertyFourCCs maps property fourCC codes to their BuildManifest field names
// This mapping was discovered through comprehensive analysis of IM4M manifests
var PropertyFourCCs = map[string]string{
	// Version and Build Properties
	"love": "ApOSLongVersion",         // Long version string (e.g., "25.1.279.5.13,0")
	"pave": "ApOSLongVersion",         // Platform version (same as love)
	"apmv": "ProductMarketingVersion", // Marketing version (e.g., "26.0")
	"vnum": "VersionNumber",           // Version number

	// Device and Platform Properties
	"prtp": "ApProductType", // Product type (e.g., "Mac14,8")
	"tagt": "ApTarget",      // Target (e.g., "J180dAP")
	"tatp": "ApTargetType",  // Target type (e.g., "j180d")
	"sdkp": "ApSDKPlatform", // SDK platform (e.g., "macosx")

	// Hardware Identifiers
	"BORD": "ApBoardID",       // Board ID
	"CHIP": "ApChipID",        // Chip ID
	"ECID": "ExclusiveChipID", // Exclusive Chip ID

	// Security Properties
	"SDOM": "ApSecurityDomain",  // Security domain
	"CEPO": "CertificateEpoch",  // Certificate epoch
	"augs": "AugmentedSecurity", // Augmented security
	"styp": "SecurityType",      // Security type
	"type": "Type",              // Type
	"clas": "DeviceClass",       // Device class
	"fchp": "FirmwareChip",      // Firmware chip

	// Cryptographic Properties
	"srvn": "SecurityRevisionNumber", // Security revision number
	"snon": "SecurityNonce",          // Security nonce
	"BNCH": "BootNonceHash",          // Boot nonce hash
	"DGST": "Digest",                 // Digest value

	// Status Properties
	"CPRO": "CertificateProductionStatus", // Certificate production status
	"CSEC": "CertificateSecurityMode",     // Certificate security mode
	"EKEY": "EncryptionKeyRequired",       // Encryption key required
	"EPRO": "EncryptionProduction",        // Encryption production
	"ESEC": "EncryptionSecurity",          // Encryption security

	// Timestamp Properties
	"tstp": "Timestamp", // Timestamp
}

// getPropertyType returns the expected type for a given property tag
func getPropertyType(tag int) PropType {
	if propType, exists := propertyTypeMap[tag]; exists {
		return propType
	}
	return PropTypeAuto // Auto-detect for unknown properties
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
