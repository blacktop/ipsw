package img4

import (
	"encoding/asn1"
	"fmt"
	"io"
	"os"

	"github.com/apex/log"
	"github.com/fatih/color"
)

// Color variables are defined in manifest.go
var (
	colorTitle    = color.New(color.Bold, color.FgHiMagenta).SprintFunc()
	colorField    = color.New(color.Bold, color.FgHiBlue).SprintFunc()
	colorSubField = color.New(color.Bold, color.FgHiCyan).SprintFunc()
)

// Core IMG4 Types
type Img4 struct {
	Name        string
	Description string
	Manifest    *Manifest
	RestoreInfo *RestoreInfo
}

type img4 struct {
	Raw         asn1.RawContent
	Name        string // IMG4
	IM4P        im4p
	Manifest    asn1.RawValue `asn1:"explicit,tag:0,optional"`
	RestoreInfo asn1.RawValue `asn1:"explicit,tag:1,optional"`
}

func Open(path string) (*img4, error) {
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
	return ParseImg4Raw(data)
}

// readBuffer reads all data from an io.Reader into a byte slice
func readBuffer(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read data: %v", err)
	}
	return data, nil
}

// ParseImg4 parses an IMG4 from an io.Reader
func ParseImg4(r io.Reader) (*img4, error) {
	data, err := readBuffer(r)
	if err != nil {
		return nil, err
	}
	return ParseImg4Raw(data)
}

// ParseImg4Raw parses an IMG4 from raw bytes
func ParseImg4Raw(data []byte) (*img4, error) {
	var img img4
	if _, err := asn1.Unmarshal(data, &img); err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse IMG4: %v", err)
	}
	return &img, nil
}

// ParseIm4m parses a standalone IM4M manifest file
func ParseIm4m(r io.Reader) (*Manifest, error) {
	data, err := readBuffer(r)
	if err != nil {
		return nil, err
	}
	return ParseManifest(data)
}

// OpenImg4 opens and parses an IMG4 file
func OpenImg4(path string) (*img4, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %v", path, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Errorf("failed to close file: %v", err)
		}
	}()
	return ParseImg4(f)
}

// Parse parses a Img4 from io.Reader
func Parse(r io.Reader) (i *Img4, err error) {
	data, err := readBuffer(r)
	if err != nil {
		return nil, err
	}
	return ParseRaw(data)
}

// ParseRaw parses a Img4 from raw bytes
func ParseRaw(data []byte) (i *Img4, err error) {
	var img img4
	if _, err := asn1.Unmarshal(data, &img); err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse Img4: %v", err)
	}

	i = &Img4{
		Name:        img.IM4P.Name,
		Description: img.IM4P.Description,
	}

	if len(img.Manifest.Bytes) > 0 {
		i.Manifest, err = ParseManifest(img.Manifest.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse manifest: %w", err)
		}
	}

	if len(img.RestoreInfo.Bytes) > 0 {
		i.RestoreInfo, err = ParseRestoreInfo(img.RestoreInfo.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse restore info: %w", err)
		}
	}

	return i, nil
}

func OpenIm4p(path string) (*Im4p, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %v", path, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Errorf("failed to close file: %v", err)
		}
	}()
	return ParseIm4p(f)
}

// CreateImg4File creates a complete IMG4 file from component files
func CreateImg4File(im4pData, manifestData, restoreInfoData []byte) ([]byte, error) {
	if len(im4pData) == 0 {
		return nil, fmt.Errorf("IM4P payload data is required")
	}

	img4Struct := img4{
		Name: "IMG4",
	}

	// Parse the IM4P data to embed it
	var im4pParsed im4p
	if _, err := asn1.Unmarshal(im4pData, &im4pParsed); err != nil {
		return nil, fmt.Errorf("failed to parse IM4P data: %v", err)
	}
	img4Struct.IM4P = im4pParsed

	// Add optional manifest data with explicit tag:0
	if len(manifestData) > 0 {
		img4Struct.Manifest = asn1.RawValue{
			Class:      2, // context-specific (for explicit tagging)
			Tag:        0, // tag:0 as specified in struct
			IsCompound: true,
			Bytes:      manifestData,
		}
	}

	// TODO: Add optional restore info data with explicit tag:1
	// if len(restoreInfoData) > 0 {
	// 	img4Struct.RestoreInfo = img4RestoreInfo{
	// 		Name: "IM4R",
	// 		Generator: asn1.RawValue{
	// 			FullBytes: restoreInfoData,
	// 		},
	// 	}
	// }

	return asn1.Marshal(img4Struct)
}

/* Validation Functions */

// ValidateImg4Structure performs structural validation on an IMG4 file
func ValidateImg4Structure(r io.Reader) (*ValidationResult, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read IMG4 data: %v", err)
	}
	img, err := ParseRaw(data)
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

func validateComponents(img *Img4, result *ValidationResult) {
	if img.Name == "" {
		result.IsValid = false
		result.Errors = append(result.Errors, "Missing IMG4 name")
	} else {
		result.Components = append(result.Components, "name")
	}

	if img.Description == "" {
		result.Warnings = append(result.Warnings, "Missing description")
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
