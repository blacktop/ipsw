package img4

import (
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/apex/log"
	"github.com/fatih/color"
)

// Color variables are defined in manifest.go
var (
	colorTitle    = color.New(color.Bold, color.FgHiMagenta).SprintFunc()
	colorField    = color.New(color.Bold, color.FgHiBlue).SprintFunc()
	colorSubField = color.New(color.Bold, color.FgHiCyan).SprintFunc()
)

type IMG4 struct {
	Raw         asn1.RawContent
	Tag         string // IMG4
	Payload     asn1.RawValue
	Manifest    asn1.RawValue `asn1:"explicit,tag:0,optional"`
	RestoreInfo asn1.RawValue `asn1:"explicit,tag:1,optional"`
}

type Image struct {
	IMG4
	Payload     *Payload
	Manifest    *Manifest
	RestoreInfo *RestoreInfo
}

func Open(path string) (*Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %v", path, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Errorf("failed to close file: %v", err)
		}
	}()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %v", path, err)
	}
	return ParseImage(data)
}

func ParseImage(data []byte) (*Image, error) {
	img := &Image{}
	
	if _, err := asn1.Unmarshal(data, &img.IMG4); err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse IMG4: %v", err)
	}

	if len(img.IMG4.Payload.Bytes) > 0 {
		payload, err := ParsePayload(img.IMG4.Payload.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse payload: %w", err)
		}
		img.Payload = payload
	}

	if len(img.IMG4.Manifest.Bytes) > 0 {
		manifest, err := ParseManifest(img.IMG4.Manifest.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse manifest: %w", err)
		}
		img.Manifest = manifest
	}

	if len(img.IMG4.RestoreInfo.Bytes) > 0 {
		restoreInfo, err := ParseRestoreInfo(img.IMG4.RestoreInfo.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse restore info: %w", err)
		}
		img.RestoreInfo = restoreInfo
	}

	return img, nil
}

// String returns a formatted string representation of the image
func (i *Image) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s:\n", colorTitle("IMG4 (Image)")))
	sb.WriteString(fmt.Sprintf("  %s: %s\n", colorField("Tag"), i.Tag))
	if i.Payload != nil {
		sb.WriteString(i.Payload.String())
	}
	if i.Manifest != nil {
		sb.WriteString(i.Manifest.String())
	}
	if i.RestoreInfo != nil {
		sb.WriteString(i.RestoreInfo.String())
	}
	return sb.String()
}

// MarshalJSON returns a JSON representation of the image
func (i *Image) MarshalJSON() ([]byte, error) {
	data := map[string]any{
		"tag":          i.Tag,
		"payload":      i.Payload.Version,
		"manifest":     i.Manifest,
		"restore_info": i.RestoreInfo,
	}
	return json.Marshal(data)
}

// CreateImg4File creates a complete IMG4 file from component files
func CreateImg4File(im4pData, manifestData, restoreInfoData []byte) ([]byte, error) {
	if len(im4pData) == 0 {
		return nil, fmt.Errorf("IM4P payload data is required")
	}

	img4Struct := IMG4{
		Tag: "IMG4",
	}

	// Parse the IM4P data to embed it
	var im4pParsed IM4P
	if _, err := asn1.Unmarshal(im4pData, &im4pParsed); err != nil {
		return nil, fmt.Errorf("failed to parse IM4P data: %v", err)
	}
	img4Struct.Payload = asn1.RawValue{
		Class:      2, // context-specific (for explicit tagging)
		Tag:        0, // tag:0 as specified in struct
		IsCompound: true,
		Bytes:      im4pData,
	}

	// Add optional manifest data with explicit tag:0
	if len(manifestData) > 0 {
		img4Struct.Manifest = asn1.RawValue{
			Class:      2, // context-specific (for explicit tagging)
			Tag:        0, // tag:0 as specified in struct
			IsCompound: true,
			Bytes:      manifestData,
		}
	}

	// Add optional restore info data with explicit tag:1
	if len(restoreInfoData) > 0 {
		img4Struct.RestoreInfo = asn1.RawValue{
			Class:      2, // context-specific (for explicit tagging)
			Tag:        1, // tag:1 as specified in struct
			IsCompound: true,
			Bytes:      restoreInfoData,
		}
	}

	return asn1.Marshal(img4Struct)
}

/* Validation Functions */

// ValidateImg4Structure performs structural validation on an IMG4 file
func ValidateImg4Structure(r io.Reader) (*ValidationResult, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read IMG4 data: %v", err)
	}
	img, err := ParseImage(data)
	if err != nil {
		return &ValidationResult{
			IsValid: false,
			Errors:  []string{fmt.Sprintf("Failed to parse IMG4: %v", err)},
		}, nil
	}

	result := &ValidationResult{
		IsValid:    true,
		Errors:     []string{},
		Warnings:   []string{},
		Structure:  "IMG4",
		Components: []string{},
	}

	validateComponents(img, result)
	return result, nil
}

func validateComponents(img *Image, result *ValidationResult) {
	if img.Tag == "" {
		result.IsValid = false
		result.Errors = append(result.Errors, "Missing IMG4 name")
	} else {
		result.Components = append(result.Components, "name")
	}

	if img.Payload.Version == "" {
		result.Warnings = append(result.Warnings, "Missing IM4P version")
	}

	// Parse manifest body to validate properties
	if img.Manifest == nil {
		result.Warnings = append(result.Warnings, "No manifest found")
	} else if len(img.Manifest.Properties) == 0 {
		result.Warnings = append(result.Warnings, "No manifest properties found")
	} else {
		result.Components = append(result.Components, "manifest")
		validateCriticalPropertiesFromSlice(img.Manifest.Properties, result)
	}
}

// validateCriticalPropertiesFromSlice validates critical properties from new []Property format
func validateCriticalPropertiesFromSlice(props []Property, result *ValidationResult) {
	criticalProps := []string{"CHIP", "BORD"}
	for _, criticalProp := range criticalProps {
		found := false
		for _, prop := range props {
			if prop.Name == criticalProp {
				found = true
				break
			}
		}
		if !found {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Missing critical property: %s", criticalProp))
		}
	}
}

// ValidationResult holds the results of IMG4 structure validation
type ValidationResult struct {
	IsValid    bool
	Structure  string
	Components []string
	Errors     []string
	Warnings   []string
}
