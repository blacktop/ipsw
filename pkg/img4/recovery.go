package img4

import (
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"strings"

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
	rest, err := asn1.Unmarshal(data, &ri.IM4R)
	if err != nil {
		return nil, &RestoreInfoError{"parse", err}
	}
	if len(rest) > 0 {
		log.Warnf("trailing data after IM4R structure: %d bytes", len(rest))
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
	maps.Copy(props, properties)
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
	return MarshalProperties(r.Properties, RestoreInfoFormat)
}

// String returns a formatted string representation of the restore info
func (r *RestoreInfo) String() string {
	var result strings.Builder
	result.WriteString(fmt.Sprintf("%s:\n", colorTitle("IM4R (Restore Info)")))
	if nonce, found := r.BootNonce(); found {
		result.WriteString(fmt.Sprintf("  %s: %d (0x%x)\n", colorField("Boot Nonce"), nonce, nonce))
	}
	result.WriteString(fmt.Sprintf("  %s: %d\n", colorField("Properties"), len(r.Properties)))
	for name, value := range r.Properties {
		result.WriteString(fmt.Sprintf("    %s: %v\n", colorSubField(name), FormatPropertyValue(value)))
	}
	return result.String()
}

func (r *RestoreInfo) MarshalJSON() ([]byte, error) {
	data := map[string]any{
		"name":       "IM4R",
		"properties": r.Properties,
	}
	
	// Safely handle boot nonce formatting
	if bncn, exists := r.Properties["BNCN"]; exists {
		switch v := bncn.(type) {
		case []byte:
			data["boot_nonce"] = fmt.Sprintf("%x", v)
		case int:
			data["boot_nonce"] = fmt.Sprintf("%x", v)
		case int64:
			data["boot_nonce"] = fmt.Sprintf("%x", v)
		case uint64:
			data["boot_nonce"] = fmt.Sprintf("%x", v)
		default:
			data["boot_nonce"] = fmt.Sprintf("%v", v)
		}
	}
	
	return json.MarshalIndent(data, "", "  ")
}
