package img4

import (
	"encoding/asn1"
	"encoding/hex"
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
	Tag         string        // IMG4
	Payload     asn1.RawValue `asn1:"explicit,tag:0,optional"`
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
	return Parse(data)
}

func Parse(data []byte) (*Image, error) {
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
		"tag": i.Tag,
	}

	if i.Payload != nil {
		payloadJSON, err := json.Marshal(i.Payload)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal payload to JSON: %v", err)
		}
		var p map[string]any
		if err := json.Unmarshal(payloadJSON, &p); err != nil {
			return nil, fmt.Errorf("failed to unmarshal payload JSON: %v", err)
		}
		data["payload"] = p
	} else {
		data["payload"] = nil
	}

	if i.Manifest != nil {
		manifestJSON, err := json.Marshal(i.Manifest)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal manifest to JSON: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(manifestJSON, &m); err != nil {
			return nil, fmt.Errorf("failed to unmarshal manifest JSON: %v", err)
		}
		data["manifest"] = m
	} else {
		data["manifest"] = nil
	}

	if i.RestoreInfo != nil {
		restoreInfoJSON, err := json.Marshal(i.RestoreInfo)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal restore info to JSON: %v", err)
		}
		var r map[string]any
		if err := json.Unmarshal(restoreInfoJSON, &r); err != nil {
			return nil, fmt.Errorf("failed to unmarshal restore info JSON: %v", err)
		}
		data["restore_info"] = r
	} else {
		data["restore_info"] = nil
	}

	return json.Marshal(data)
}

type CreateConfig struct {
	// raw IM4P data
	InputData          []byte
	PayloadType        string
	PayloadVersion     string
	PayloadCompression string
	PayloadExtraData   []byte

	PayloadData     []byte
	ManifestData    []byte
	RestoreInfoData []byte

	// IM4R specific
	BootNonce string
}

// Create creates a complete IMG4 file from component files
func Create(conf *CreateConfig) (*Image, error) {
	var err error

	if conf.InputData == nil && conf.PayloadData == nil {
		return nil, fmt.Errorf("config must contain either InputData or PayloadData")
	}

	img := Image{
		IMG4: IMG4{
			Tag: "IMG4",
		},
	}

	if len(conf.InputData) > 0 {
		var comp CompressionAlgorithm
		switch strings.ToLower(conf.PayloadCompression) {
		case "lzss":
			comp = CompressionAlgorithmLZSS
		case "lzfse":
			comp = CompressionAlgorithmLZFSE
		}
		img.Payload, err = CreatePayload(&CreatePayloadConfig{
			Type:        conf.PayloadType,
			Version:     conf.PayloadVersion,
			Data:        conf.InputData,
			ExtraData:   conf.PayloadExtraData,
			Compression: comp,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create IM4P payload from input data: %v", err)
		}
	} else if len(conf.PayloadData) > 0 {
		img.Payload, err = ParsePayload(conf.PayloadData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse IM4P payload data: %v", err)
		}
	}

	if len(conf.ManifestData) > 0 {
		img.Manifest, err = ParseManifest(conf.ManifestData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse IM4M manifest data: %v", err)
		}
	}

	if len(conf.RestoreInfoData) > 0 {
		img.RestoreInfo, err = ParseRestoreInfo(conf.RestoreInfoData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse IM4R restore info data: %v", err)
		}
	}
	if len(conf.BootNonce) > 0 {
		nonce, err := hex.DecodeString(conf.BootNonce)
		if err != nil {
			return nil, fmt.Errorf("failed to decode boot nonce: %v", err)
		}
		if len(nonce) != 8 {
			return nil, fmt.Errorf("boot nonce must be exactly %d bytes (%d hex characters), got %d bytes", 8, 16, len(nonce))
		}
		img.RestoreInfo, err = CreateRestoreInfo(nonce)
		if err != nil {
			return nil, fmt.Errorf("failed to create IM4R restore info with boot nonce: %v", err)
		}
	}

	return &img, nil
}

func (i *Image) Marshal() ([]byte, error) {
	if i.Payload != nil {
		payloadData, err := i.Payload.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal payload: %v", err)
		}
		i.IMG4.Payload = asn1.RawValue{
			Class:      2, // context-specific (for explicit tagging)
			Tag:        0, // tag:0 as specified in struct
			IsCompound: true,
			Bytes:      payloadData,
		}
	}

	if i.Manifest != nil {
		manifestData, err := i.Manifest.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal manifest: %v", err)
		}
		i.IMG4.Manifest = asn1.RawValue{
			Class:      2, // context-specific (for explicit tagging)
			Tag:        0, // tag:0 as specified in struct
			IsCompound: true,
			Bytes:      manifestData,
		}
	}

	if i.RestoreInfo != nil {
		restoreInfoData, err := i.RestoreInfo.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal restore info: %v", err)
		}
		i.IMG4.RestoreInfo = asn1.RawValue{
			Class:      2, // context-specific (for explicit tagging)
			Tag:        1, // tag:1 as specified in struct
			IsCompound: true,
			Bytes:      restoreInfoData,
		}
	}

	return asn1.Marshal(i.IMG4)
}

/* Validation Functions */

// ValidateImg4Structure performs structural validation on an IMG4 file
func ValidateImg4Structure(r io.Reader) (*ValidationResult, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read IMG4 data: %v", err)
	}
	img, err := Parse(data)
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
