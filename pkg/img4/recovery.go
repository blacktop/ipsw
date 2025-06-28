package img4

import (
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/apex/log"
)

type IM4R struct {
	Raw               asn1.RawContent
	Tag               string `asn1:"ia5"`
	RestoreProperties asn1.RawValue
}

// RestoreInfo represents an IM4R (Image4 Restore Info) structure
type RestoreInfo struct {
	IM4R
	Properties map[string]any
}

// RestoreInfoError represents parsing errors with context
type RestoreInfoError struct {
	Op  string // Operation that failed
	Err error  // Underlying error
}

func (e *RestoreInfoError) Error() string {
	return fmt.Sprintf("restore info %s: %v", e.Op, e.Err)
}

func (e *RestoreInfoError) Unwrap() error {
	return e.Err
}

func OpenRestoreInfo(path string) (*RestoreInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open restore info %s: %v", path, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Errorf("failed to close restore info %s: %v", path, err)
		}
	}()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read restore info %s: %v", path, err)
	}

	return ParseRestoreInfo(data)
}

// ParseRestoreInfo parses a standalone IM4R file and returns the restore info
func ParseRestoreInfo(data []byte) (*RestoreInfo, error) {
	var ri RestoreInfo
	if _, err := asn1.Unmarshal(data, &ri.IM4R); err != nil {
		return nil, &RestoreInfoError{"parse", err}
	}

	if ri.Tag != "IM4R" {
		return nil, &RestoreInfoError{"validate", fmt.Errorf("invalid magic: expected 'IM4R', got '%s'", ri.Tag)}
	}

	properties, err := ParsePropertyMap(ri.RestoreProperties.Bytes)
	if err != nil {
		return nil, &RestoreInfoError{"parse properties", err}
	}

	ri.Properties = properties

	return &ri, nil
}

// BootNonce returns the boot nonce (BNCN) value if present
func (r *RestoreInfo) BootNonce() (uint64, bool) {
	value, exists := r.Properties["BNCN"]
	if !exists {
		return 0, false
	}

	switch v := value.(type) {
	case int:
		return uint64(v), true
	case int64:
		return uint64(v), true
	case uint64:
		return v, true
	default:
		return 0, false
	}
}

// Get returns the value of a property by name
func (r *RestoreInfo) Get(name string) (any, bool) {
	value, exists := r.Properties[name]
	return value, exists
}

// Has checks if a property exists
func (r *RestoreInfo) Has(name string) bool {
	_, exists := r.Properties[name]
	return exists
}

// NewWithBootNonce creates a new RestoreInfo with only a boot nonce
func NewWithBootNonce(nonce uint64) *RestoreInfo {
	return &RestoreInfo{
		IM4R: IM4R{
			Tag: "IM4R",
		},
		Properties: map[string]any{"BNCN": nonce},
	}
}

// New creates a new RestoreInfo with the given properties
func New(properties map[string]any) *RestoreInfo {
	// Make a copy to avoid external modifications
	props := make(map[string]any, len(properties))
	for k, v := range properties {
		props[k] = v
	}
	return &RestoreInfo{
		IM4R: IM4R{
			Tag: "IM4R",
		},
		Properties: props,
	}
}

// CreateRestoreInfo creates RestoreInfo from a boot nonce value
func CreateRestoreInfo(nonce any) (*RestoreInfo, error) {
	var nonceValue uint64

	switch v := nonce.(type) {
	case uint64:
		nonceValue = v
	case []byte:
		if len(v) != 8 {
			return nil, fmt.Errorf("boot nonce bytes must be exactly 8 bytes, got %d", len(v))
		}
		nonceValue = binary.BigEndian.Uint64(v)
	default:
		return nil, fmt.Errorf("unsupported nonce type: %T", nonce)
	}

	return NewWithBootNonce(nonceValue), nil
}

// Marshal marshals the RestoreInfo to ASN.1 bytes (IM4R format)
func (r *RestoreInfo) Marshal() ([]byte, error) {
	restorePropertiesData, err := r.marshalProperties()
	if err != nil {
		return nil, &RestoreInfoError{"marshal properties", err}
	}

	im4r := IM4R{
		Tag: "IM4R",
		RestoreProperties: asn1.RawValue{
			Bytes: restorePropertiesData,
		},
	}

	data, err := asn1.Marshal(im4r)
	if err != nil {
		return nil, &RestoreInfoError{"marshal", err}
	}
	return data, nil
}

// marshalProperties marshals the properties map to ASN.1 format
func (r *RestoreInfo) marshalProperties() ([]byte, error) {
	var entries []asn1.RawValue

	for name, value := range r.Properties {
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
			valueBytes, err = asn1.Marshal(int64(v))
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
			return nil, fmt.Errorf("unsupported property type: %T", v)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to marshal property %s: %v", name, err)
		}

		// Create property structure
		propStruct := struct {
			Name  string
			Value asn1.RawValue
		}{
			Name: name,
			Value: asn1.RawValue{
				Tag:       tag,
				FullBytes: valueBytes, // Use full bytes including header
			},
		}

		propBytes, err := asn1.Marshal(propStruct)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal property %s: %v", name, err)
		}

		entries = append(entries, asn1.RawValue{
			Class:      3, // private class
			Tag:        fourCCtoInt(name),
			IsCompound: true,
			Bytes:      propBytes,
		})
	}

	// Concatenate all entries directly (no outer SEQUENCE wrapper)
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

// String returns a formatted string representation of the restore info
func (r *RestoreInfo) String() string {
	var result strings.Builder
	result.WriteString(fmt.Sprintf("%s:\n", colorTitle("IM4R (Restore Info)")))
	result.WriteString(fmt.Sprintf("  %s: %d\n", colorField("Properties"), len(r.Properties)))
	if nonce, found := r.BootNonce(); found {
		result.WriteString(fmt.Sprintf("  %s: %d (0x%x)\n", colorField("Boot Nonce"), nonce, nonce))
	}
	for name, value := range r.Properties {
		result.WriteString(fmt.Sprintf("    %s: %v\n", colorSubField(name), FormatPropertyValue(value)))
	}
	return result.String()
}

func (r *RestoreInfo) MarshalJSON() ([]byte, error) {
	data := map[string]any{
		"name":       "IM4R",
		"boot_nonce": fmt.Sprintf("%x", r.Properties["BNCN"]),
		"properties": r.Properties,
	}
	return json.MarshalIndent(data, "", "  ")
}
