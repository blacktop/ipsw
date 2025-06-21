package img4

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/apex/log"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/lzfse-cgo"
)

// Img4 object
type Img4 struct {
	Name        string
	Description string
	Manifest    manifest
	RestoreInfo restoreInfo
}

type manifest struct {
	Properties   ManifestProperties
	ApImg4Ticket asn1.RawValue
	img4Manifest
}

type restoreInfo struct {
	Generator dataProp
	img4RestoreInfo
}

type img4 struct {
	Raw         asn1.RawContent
	Name        string // IMG4
	IM4P        im4p
	Manifest    asn1.RawValue   `asn1:"explicit,tag:0,optional"`
	RestoreInfo img4RestoreInfo `asn1:"explicit,tag:1,optional"`
}

type Im4p struct {
	im4p
	Kbags []Keybag
}

type im4p struct {
	Raw         asn1.RawContent
	Name        string `asn1:"ia5"` // IM4P
	Type        string `asn1:"ia5"`
	Description string `asn1:"ia5"`
	Data        []byte
	KbagData    []byte `asn1:"optional"`
}

type kbagType int

const (
	PRODUCTION  kbagType = 1
	DEVELOPMENT kbagType = 2
	DECRYPTED   kbagType = 3
)

func (t kbagType) String() string {
	switch t {
	case PRODUCTION:
		return "PRODUCTION"
	case DEVELOPMENT:
		return "DEVELOPMENT"
	case DECRYPTED:
		return "DECRYPTED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}
func (t kbagType) Short() string {
	switch t {
	case PRODUCTION:
		return "prod"
	case DEVELOPMENT:
		return "dev"
	case DECRYPTED:
		return "dec"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

type Keybag struct {
	Type kbagType
	IV   []byte
	Key  []byte
}

func (k Keybag) String() string {
	return fmt.Sprintf(
		"-\n"+
			"  type: %s\n"+
			"    iv: %x\n"+
			"   key: %x",
		k.Type.String(),
		k.IV,
		k.Key)
}
func (k Keybag) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Type string `json:"type,omitempty"`
		IV   string `json:"iv,omitempty"`
		Key  string `json:"key,omitempty"`
	}{
		Type: k.Type.Short(),
		IV:   hex.EncodeToString(k.IV),
		Key:  hex.EncodeToString(k.Key),
	})
}

const typeBNCN = "private,tag:1112425294"

type img4RestoreInfo struct {
	Raw       asn1.RawContent
	Name      string // IM4R
	Generator asn1.RawValue
}

type img4Manifest struct {
	Raw     asn1.RawContent
	Name    string // IM4M
	Version int
	Body    asn1.RawValue
	Data    []byte
}

const typeMANB = "private,tag:1296125506"

type manifestBody struct {
	Raw        asn1.RawContent
	Name       string // MANB
	Properties asn1.RawValue
}

const typeMANP = "private,tag:1296125520"

type manifestProperties struct {
	Raw        asn1.RawContent
	Name       string // MANP
	Properties asn1.RawValue
}

type idProp struct {
	Raw  asn1.RawContent
	Name string
	ID   int
}

type dataProp struct {
	Raw  asn1.RawContent
	Name string
	Data []byte
}

type boolProp struct {
	Raw  asn1.RawContent
	Name string
	Bool bool
}

type ManifestProperties map[string]any

const typeBNCH = "private,tag:1112425288"

type BNCH struct {
	dataProp
}

const typeBORD = "private,tag:1112494660"

type BORD struct {
	idProp
}

const typeCEPO = "private,tag:1128616015"

type CEPO struct {
	idProp
}

const typeCHIP = "private,tag:1128810832"

type CHIP struct {
	idProp
}

const typeCPRO = "private,tag:1129337423"

type CPRO struct {
	boolProp
}

const typeCSEC = "private,tag:1129530691"

type CSEC struct {
	boolProp
}

const typeECID = "private,tag:1162037572"

type ECID struct {
	idProp
}

const typeSDOM = "private,tag:1396985677"

type SDOM struct {
	idProp
}

const typeSnon = "private,tag:1936617326"

type snon struct {
	dataProp
}

const typeSrvn = "private,tag:1936881262"

type srvn struct {
	dataProp
}

const ( // sepi private tags
	typeImpl = "private,tag:1768779884"
	typeArms = "private,tag:1634889075"
	typeTbmr = "private,tag:1952607602"
	typeTbms = "private,tag:1952607603"
	typeTz0s = "private,tag:1954164851"
)

type arms struct {
	idProp
}
type tbmr struct {
	dataProp
}
type tbms struct {
	dataProp
}
type tz0s struct {
	idProp
}

func parseDataProp(data []byte, pType string) (*dataProp, []byte, error) {
	var d []dataProp
	rest, err := asn1.UnmarshalWithParams(data, &d, pType)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to ASN.1 parse data property: %v", err)
	}
	return &d[0], rest, nil
}

func parseIDProp(data []byte, pType string) (*idProp, []byte, error) {
	var i []idProp
	rest, err := asn1.UnmarshalWithParams(data, &i, pType)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to ASN.1 parse id property: %v", err)
	}
	return &i[0], rest, nil
}

func parseBoolProp(data []byte, pType string) (*boolProp, []byte, error) {
	var b []boolProp
	rest, err := asn1.UnmarshalWithParams(data, &b, pType)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to ASN.1 parse bool property: %v", err)
	}
	return &b[0], rest, nil
}

func parseManifestProperties(data []byte) (*ManifestProperties, error) {
	mProps := make(ManifestProperties)
	// parse BNCH
	dProp, rest, err := parseDataProp(data, typeBNCH)
	if err != nil {
		return nil, err
	}
	mProps[dProp.Name] = dProp.Data
	// parse BORD
	iProp, rest, err := parseIDProp(rest, typeBORD)
	if err != nil {
		return nil, err
	}
	mProps[iProp.Name] = iProp.ID
	// parse CEPO
	iProp, rest, err = parseIDProp(rest, typeCEPO)
	if err != nil {
		return nil, err
	}
	mProps[iProp.Name] = iProp.ID
	// parse CHIP
	iProp, rest, err = parseIDProp(rest, typeCHIP)
	if err != nil {
		return nil, err
	}
	mProps[iProp.Name] = iProp.ID
	// parse CPRO
	bProp, rest, err := parseBoolProp(rest, typeCPRO)
	if err != nil {
		return nil, err
	}
	mProps[bProp.Name] = bProp.Bool
	// parse CSEC
	bProp, rest, err = parseBoolProp(rest, typeCSEC)
	if err != nil {
		return nil, err
	}
	mProps[bProp.Name] = bProp.Bool
	// parse ECID
	iProp, rest, err = parseIDProp(rest, typeECID)
	if err != nil {
		return nil, err
	}
	mProps[iProp.Name] = iProp.ID
	// parse SDOM
	iProp, rest, err = parseIDProp(rest, typeSDOM)
	if err != nil {
		return nil, err
	}
	mProps[iProp.Name] = iProp.ID
	// parse snon
	dProp, rest, err = parseDataProp(rest, typeSnon)
	if err != nil {
		return nil, err
	}
	mProps[dProp.Name] = dProp.Data
	// parse srvn
	dProp, rest, err = parseDataProp(rest, typeSrvn)
	if err != nil {
		return nil, err
	}
	mProps[dProp.Name] = dProp.Data

	return &mProps, nil
}

// Parse parses a Img4
func Parse(r io.Reader) (*Img4, error) {
	data := new(bytes.Buffer)
	data.ReadFrom(r)

	var i img4

	_, err := asn1.Unmarshal(data.Bytes(), &i)
	if err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse Img4: %v", err)
	}

	result := &Img4{
		Name:        i.IM4P.Name,
		Description: i.IM4P.Description,
	}

	// Parse manifest if present (optional)
	if len(i.Manifest.Bytes) > 0 {
		var m img4Manifest
		_, err = asn1.Unmarshal(i.Manifest.Bytes, &m)
		if err != nil {
			return nil, fmt.Errorf("failed to ASN.1 parse Img4 manifest: %v", err)
		}

		var mb []manifestBody
		_, err = asn1.UnmarshalWithParams(m.Body.Bytes, &mb, typeMANB)
		if err != nil {
			return nil, fmt.Errorf("failed to ASN.1 parse Img4 manifest body: %v", err)
		}

		var mProps []manifestProperties
		_, err = asn1.UnmarshalWithParams(mb[0].Properties.Bytes, &mProps, typeMANP)
		if err != nil {
			return nil, fmt.Errorf("failed to ASN.1 parse Img4 manifest properties: %v", err)
		}

		props, err := parseManifestProperties(mProps[0].Properties.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to ASN.1 parse Img4 manifest property: %v", err)
		}

		result.Manifest = manifest{
			Properties:   *props,
			ApImg4Ticket: i.Manifest,
			img4Manifest: m,
		}
	}

	// Parse restore info if present (optional)
	if i.RestoreInfo.Name != "" {
		gen, _, err := parseDataProp(i.RestoreInfo.Generator.Bytes, typeBNCN)
		if err != nil {
			return nil, fmt.Errorf("failed to ASN.1 parse Generator: %v", err)
		}

		result.RestoreInfo = restoreInfo{
			Generator:       *gen,
			img4RestoreInfo: i.RestoreInfo,
		}
	}

	return result, nil
}

func OpenIm4p(path string) (*Im4p, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseIm4p(f)
}

func ParseIm4p(r io.Reader) (*Im4p, error) {

	data := new(bytes.Buffer)
	data.ReadFrom(r)

	var i Im4p

	_, err := asn1.Unmarshal(data.Bytes(), &i.im4p)
	if err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse Im4p: %v", err)
	}

	if i.im4p.KbagData != nil {
		_, err = asn1.Unmarshal(i.im4p.KbagData, &i.Kbags)
		if err != nil {
			return nil, fmt.Errorf("failed to ASN.1 parse Im4p KBAG: %v", err)
		}
	}

	return &i, nil
}

func OpenImg4(path string) (*img4, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseImg4(f)
}

func ParseImg4(r io.Reader) (*img4, error) {

	data := new(bytes.Buffer)
	data.ReadFrom(r)

	var i img4

	if _, err := asn1.Unmarshal(data.Bytes(), &i); err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse Img4: %v", err)
	}

	return &i, nil
}

type im4pKBag struct {
	Name    string   `json:"name,omitempty"`
	Keybags []Keybag `json:"kbags,omitempty"`
}

type KeyBags struct {
	Type    string
	Version string
	Build   string
	Devices []string
	Files   []im4pKBag
}

// MetaData contains minimal metadata needed for key bag parsing
type MetaData struct {
	Type                  string
	ProductVersion        string
	ProductBuildVersion   string
	SupportedProductTypes []string
}

func (kbs KeyBags) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Type    string     `json:"type,omitempty"`
		Version string     `json:"version,omitempty"`
		Build   string     `json:"build,omitempty"`
		Devices []string   `json:"devices,omitempty"`
		Files   []im4pKBag `json:"files,omitempty"`
	}{
		Type:    kbs.Type,
		Version: kbs.Version,
		Build:   kbs.Build,
		Devices: kbs.Devices,
		Files:   kbs.Files,
	})
}

func ParseZipKeyBags(files []*zip.File, meta *MetaData, pattern string) (*KeyBags, error) {
	kbags := &KeyBags{
		Type:    meta.Type,
		Version: meta.ProductVersion,
		Build:   meta.ProductBuildVersion,
		Devices: meta.SupportedProductTypes,
	}

	rePattern := `.*im4p$`
	if len(pattern) > 0 {
		if _, err := regexp.Compile(pattern); err != nil {
			return nil, fmt.Errorf("failed to compile --pattern regexp: %v", err)
		}
		rePattern = pattern
	}

	for _, f := range files {
		if regexp.MustCompile(rePattern).MatchString(f.Name) {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("error opening zipped file %s: %v", f.Name, err)
			}
			im4p, err := ParseIm4p(rc)
			if err != nil {
				log.Errorf("failed to parse im4p %s: %v", f.Name, err)
			}
			if im4p.Kbags == nil { // kbags are optional
				continue
			}
			kbags.Files = append(kbags.Files, im4pKBag{
				Name:    filepath.Base(f.Name),
				Keybags: im4p.Kbags,
			})
			rc.Close()
		}
	}

	return kbags, nil
}

// CreateIm4p creates a new IM4P structure
func CreateIm4p(name, fourcc, description string, data []byte, kbags []Keybag) *Im4p {
	im4pStruct := &Im4p{
		im4p: im4p{
			Name:        name,
			Type:        fourcc,
			Description: description,
			Data:        data,
		},
		Kbags: kbags,
	}

	// If there are keybags, marshal them to KbagData
	if len(kbags) > 0 {
		if kbagData, err := asn1.Marshal(kbags); err == nil {
			im4pStruct.im4p.KbagData = kbagData
		}
	}

	return im4pStruct
}

// MarshalIm4p marshals an IM4P structure to ASN.1 bytes
func MarshalIm4p(im4p *Im4p) ([]byte, error) {
	return asn1.Marshal(im4p.im4p)
}

// CreateIm4pFile creates a complete IM4P file from raw data
func CreateIm4pFile(fourcc, description string, data []byte) ([]byte, error) {
	if len(fourcc) != 4 {
		return nil, fmt.Errorf("FourCC must be exactly 4 characters, got %d: %s", len(fourcc), fourcc)
	}

	im4pStruct := CreateIm4p("IM4P", fourcc, description, data, nil)
	return MarshalIm4p(im4pStruct)
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
			FullBytes: manifestData,
		}
	}

	// Add optional restore info data with explicit tag:1
	if len(restoreInfoData) > 0 {
		img4Struct.RestoreInfo = img4RestoreInfo{
			Name: "IM4R",
			Generator: asn1.RawValue{
				FullBytes: restoreInfoData,
			},
		}
	}

	return asn1.Marshal(img4Struct)
}

// DetectFileType attempts to detect if a file is IMG4 or IM4P by examining its structure
func DetectFileType(r io.Reader) (string, error) {
	data := new(bytes.Buffer)
	data.ReadFrom(r)
	dataBytes := data.Bytes()

	var img4Test img4
	if _, err := asn1.Unmarshal(dataBytes, &img4Test); err == nil && img4Test.Name == "IMG4" {
		return "IMG4", nil
	}

	var im4pTest im4p
	if _, err := asn1.Unmarshal(dataBytes, &im4pTest); err == nil && im4pTest.Name == "IM4P" {
		return "IM4P", nil
	}

	return "", fmt.Errorf("unknown file type - not IMG4 or IM4P")
}

// ExtractManifestFromShsh extracts IM4M manifest from SHSH blob with proper ASN.1 parsing
func ExtractManifestFromShsh(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read SHSH data: %v", err)
	}

	// SHSH blobs are typically plist files containing base64-encoded manifests
	// Look for common patterns in SHSH blob structure

	// Look for direct IM4M signature in the data
	im4mSig := []byte("IM4M")
	if idx := bytes.Index(data, im4mSig); idx != -1 {
		return extractManifestFromRawData(data, idx)
	}

	// Look for base64-encoded IM4M (common in SHSH blobs)
	// SHSH blobs often contain "IM4M" base64-encoded as "SU00TQ=="
	if bytes.Contains(data, []byte("<key>ApImg4Ticket</key>")) {
		// This is likely a plist with base64-encoded ticket
		return extractManifestFromPlistShsh(data)
	}

	// Look for XML plist structure with ApImg4Ticket
	if bytes.Contains(data, []byte("ApImg4Ticket")) {
		return extractManifestFromPlistShsh(data)
	}

	return nil, fmt.Errorf("no recognizable IM4M manifest found in SHSH blob")
}

func extractManifestFromRawData(data []byte, startIdx int) ([]byte, error) {
	// Start from the IM4M signature
	manifestStart := startIdx

	// Parse ASN.1 structure to find the actual end of the manifest
	// This is more robust than the simple search we had before
	remainder := data[manifestStart:]

	// Try to parse the ASN.1 structure to determine the correct length
	var manifest img4Manifest
	if _, err := asn1.Unmarshal(remainder, &manifest); err == nil {
		// Successfully parsed - use the Raw content to get the exact bytes
		return manifest.Raw, nil
	}

	// Fallback to the simple approach if ASN.1 parsing fails
	manifestEnd := len(data)
	for i := manifestStart + 4; i < len(data)-3; i++ {
		if bytes.Equal(data[i:i+4], []byte("IM4R")) ||
			bytes.Equal(data[i:i+4], []byte("IM4P")) {
			manifestEnd = i
			break
		}
	}

	if manifestEnd <= manifestStart+4 {
		return nil, fmt.Errorf("invalid manifest structure in SHSH blob")
	}

	return data[manifestStart:manifestEnd], nil
}

func extractManifestFromPlistShsh(data []byte) ([]byte, error) {
	// SHSH blobs from TSS are plist files with ApImg4Ticket field
	var shsh struct {
		ApImg4Ticket []byte `plist:"ApImg4Ticket"`
		Generator    string `plist:"generator,omitempty"`
		BBTicket     []byte `plist:"BBTicket,omitempty"`
	}
	
	// Try to decode as plist
	decoder := plist.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&shsh); err != nil {
		return nil, fmt.Errorf("failed to decode SHSH plist: %v", err)
	}
	
	if len(shsh.ApImg4Ticket) == 0 {
		return nil, fmt.Errorf("no ApImg4Ticket found in SHSH plist")
	}
	
	// The ApImg4Ticket contains the raw IM4M manifest
	return shsh.ApImg4Ticket, nil
}

// ValidateImg4Structure performs structural validation on an IMG4 file
func ValidateImg4Structure(r io.Reader) (*ValidationResult, error) {
	img, err := Parse(r)
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

	// Check for required components
	if img.Name == "" {
		result.IsValid = false
		result.Errors = append(result.Errors, "Missing IMG4 name")
	} else {
		result.Components = append(result.Components, "name")
	}

	if img.Description == "" {
		result.Warnings = append(result.Warnings, "Missing description")
	}

	// Check manifest properties
	if len(img.Manifest.Properties) == 0 {
		result.Warnings = append(result.Warnings, "No manifest properties found")
	} else {
		result.Components = append(result.Components, "manifest")

		// Check for critical properties
		criticalProps := []string{"CHIP", "BORD"}
		for _, prop := range criticalProps {
			if _, exists := img.Manifest.Properties[prop]; !exists {
				result.Warnings = append(result.Warnings, fmt.Sprintf("Missing critical property: %s", prop))
			}
		}
	}

	return result, nil
}

// ValidationResult holds the results of IMG4 structure validation
type ValidationResult struct {
	IsValid    bool
	Structure  string
	Components []string
	Errors     []string
	Warnings   []string
}

// DecryptPayload decrypts an IM4P payload using AES-CBC with provided IV and key
func DecryptPayload(path, output string, iv, key []byte) error {
	var r io.Reader

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("unable to open file %s: %v", path, err)
	}
	defer f.Close()

	i, err := ParseIm4p(f)
	if err != nil {
		return fmt.Errorf("unable to parse IM4P: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %v", err)
	}

	if len(i.Data) < aes.BlockSize {
		return fmt.Errorf("IM4P data too short")
	}

	// CBC mode always works in whole blocks
	if (len(i.Data) % aes.BlockSize) != 0 {
		return fmt.Errorf("IM4P data is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(i.Data, i.Data)

	of, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %v", output, err)
	}
	defer of.Close()

	// Check for LZFSE compression and decompress if needed
	if len(i.Data) >= 4 && bytes.Equal(i.Data[:4], []byte("bvx2")) {
		log.Debug("Detected LZFSE compression")
		decompressed := lzfse.DecodeBuffer(i.Data)
		if len(decompressed) == 0 {
			return fmt.Errorf("failed to LZFSE decompress %s", path)
		}
		r = bytes.NewReader(decompressed)
	} else {
		r = bytes.NewReader(i.Data)
	}

	if _, err = io.Copy(of, r); err != nil {
		return fmt.Errorf("failed to decompress to file %s: %v", output, err)
	}

	return nil
}

// ExtractPayload extracts payload data from IMG4 or IM4P files with optional decompression
func ExtractPayload(inputPath, outputPath string, isImg4 bool) error {
	f, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer f.Close()

	var payloadData []byte

	if isImg4 {
		i, err := ParseImg4(f)
		if err != nil {
			return fmt.Errorf("failed to parse IMG4: %v", err)
		}
		payloadData = i.IM4P.Data
	} else {
		i, err := ParseIm4p(f)
		if err != nil {
			return fmt.Errorf("failed to parse IM4P: %v", err)
		}
		payloadData = i.Data
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o750); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", filepath.Dir(outputPath), err)
	}

	// Check for LZFSE compression and decompress if needed
	if len(payloadData) >= 4 && bytes.Equal(payloadData[:4], []byte("bvx2")) {
		log.Debug("Detected LZFSE compression")
		decompressed := lzfse.DecodeBuffer(payloadData)
		if len(decompressed) == 0 {
			return fmt.Errorf("failed to LZFSE decompress %s", inputPath)
		}
		payloadData = decompressed
	}

	return os.WriteFile(outputPath, payloadData, 0o660)
}
