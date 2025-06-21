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

// ASN.1 Private Tag Constants
const (
	// Manifest tags
	typeMANB = "private,tag:1296125506" // MANB
	typeMANP = "private,tag:1296125520" // MANP
	typeBNCN = "private,tag:1112425294" // BNCN

	// Manifest property tags
	typeBNCH = "private,tag:1112425288" // BNCH
	typeBORD = "private,tag:1112494660" // BORD
	typeCEPO = "private,tag:1128616015" // CEPO
	typeCHIP = "private,tag:1128810832" // CHIP
	typeCPRO = "private,tag:1129337423" // CPRO
	typeCSEC = "private,tag:1129530691" // CSEC
	typeECID = "private,tag:1162037572" // ECID
	typeSDOM = "private,tag:1396985677" // SDOM
	typeSnon = "private,tag:1936617326" // snon
	typeSrvn = "private,tag:1936881262" // srvn

	// SEPI tags
	typeImpl = "private,tag:1768779884" // impl
	typeArms = "private,tag:1634889075" // arms
	typeTbmr = "private,tag:1952607602" // tbmr
	typeTbms = "private,tag:1952607603" // tbms
	typeTz0s = "private,tag:1954164851" // tz0s
)

// Core IMG4 Types
type Img4 struct {
	Name        string
	Description string
	Manifest    Manifest
	RestoreInfo RestoreInfo
}

type Manifest struct {
	Properties   ManifestProperties
	ApImg4Ticket asn1.RawValue
	img4Manifest
}

type RestoreInfo struct {
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

// IM4P Types
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

// Keybag Types
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

// Internal ASN.1 Types
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

type manifestBody struct {
	Raw        asn1.RawContent
	Name       string // MANB
	Properties asn1.RawValue
}

type manifestProperties struct {
	Raw        asn1.RawContent
	Name       string // MANP
	Properties asn1.RawValue
}

// Property Types
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

// Specific Property Types (embedded types for organization)
type (
	BNCH struct{ dataProp }
	BORD struct{ idProp }
	CEPO struct{ idProp }
	CHIP struct{ idProp }
	CPRO struct{ boolProp }
	CSEC struct{ boolProp }
	ECID struct{ idProp }
	SDOM struct{ idProp }
	snon struct{ dataProp }
	srvn struct{ dataProp }
	arms struct{ idProp }
	tbmr struct{ dataProp }
	tbms struct{ dataProp }
	tz0s struct{ idProp }
)

// Common buffer reading helper
func readBuffer(r io.Reader) ([]byte, error) {
	data := new(bytes.Buffer)
	if _, err := data.ReadFrom(r); err != nil {
		return nil, fmt.Errorf("failed to read data: %v", err)
	}
	return data.Bytes(), nil
}

// Generic property parser
func parseProperty[T any](data []byte, pType string) (*T, []byte, error) {
	var props []T
	rest, err := asn1.UnmarshalWithParams(data, &props, pType)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to ASN.1 parse property %s: %v", pType, err)
	}
	if len(props) == 0 {
		return nil, nil, fmt.Errorf("no properties found for type %s", pType)
	}
	return &props[0], rest, nil
}

// Specific property parsers (for backward compatibility)
func parseDataProp(data []byte, pType string) (*dataProp, []byte, error) {
	return parseProperty[dataProp](data, pType)
}

func parseIDProp(data []byte, pType string) (*idProp, []byte, error) {
	return parseProperty[idProp](data, pType)
}

func parseBoolProp(data []byte, pType string) (*boolProp, []byte, error) {
	return parseProperty[boolProp](data, pType)
}

// Property definition for ordered parsing
type propertyDef struct {
	tag       string
	parseFunc func([]byte, string) (any, []byte, error)
	storeFunc func(ManifestProperties, string, any)
}

var manifestPropertyDefs = []propertyDef{
	{typeBNCH, parseDataProperty, storeDataProperty},
	{typeBORD, parseIDProperty, storeIDProperty},
	{typeCEPO, parseIDProperty, storeIDProperty},
	{typeCHIP, parseIDProperty, storeIDProperty},
	{typeCPRO, parseBoolProperty, storeBoolProperty},
	{typeCSEC, parseBoolProperty, storeBoolProperty},
	{typeECID, parseIDProperty, storeIDProperty},
	{typeSDOM, parseIDProperty, storeIDProperty},
	{typeSnon, parseDataProperty, storeDataProperty},
	{typeSrvn, parseDataProperty, storeDataProperty},
}

// Property parsers and storage functions
func parseDataProperty(data []byte, pType string) (any, []byte, error) {
	return parseDataProp(data, pType)
}

func parseIDProperty(data []byte, pType string) (any, []byte, error) {
	return parseIDProp(data, pType)
}

func parseBoolProperty(data []byte, pType string) (any, []byte, error) {
	return parseBoolProp(data, pType)
}

func storeDataProperty(props ManifestProperties, name string, value any) {
	if prop, ok := value.(*dataProp); ok {
		props[prop.Name] = prop.Data
	}
}

func storeIDProperty(props ManifestProperties, name string, value any) {
	if prop, ok := value.(*idProp); ok {
		props[prop.Name] = prop.ID
	}
}

func storeBoolProperty(props ManifestProperties, name string, value any) {
	if prop, ok := value.(*boolProp); ok {
		props[prop.Name] = prop.Bool
	}
}

func parseManifestProperties(data []byte) (*ManifestProperties, error) {
	mProps := make(ManifestProperties)
	remaining := data

	for _, def := range manifestPropertyDefs {
		value, rest, err := def.parseFunc(remaining, def.tag)
		if err != nil {
			return nil, fmt.Errorf("failed to parse property %s: %v", def.tag, err)
		}
		def.storeFunc(mProps, def.tag, value)
		remaining = rest
	}

	return &mProps, nil
}

// Parse parses a Img4
func Parse(r io.Reader) (*Img4, error) {
	data, err := readBuffer(r)
	if err != nil {
		return nil, err
	}

	var i img4
	if _, err := asn1.Unmarshal(data, &i); err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse Img4: %v", err)
	}

	result := &Img4{
		Name:        i.IM4P.Name,
		Description: i.IM4P.Description,
	}

	// Parse manifest if present
	if err := parseManifest(&i, result); err != nil {
		return nil, err
	}

	// Parse restore info if present
	if err := parseRestoreInfo(&i, result); err != nil {
		return nil, err
	}

	return result, nil
}

func parseManifest(i *img4, result *Img4) error {
	if len(i.Manifest.Bytes) == 0 {
		return nil
	}

	var m img4Manifest
	if _, err := asn1.Unmarshal(i.Manifest.Bytes, &m); err != nil {
		return fmt.Errorf("failed to ASN.1 parse Img4 manifest: %v", err)
	}

	var mb []manifestBody
	if _, err := asn1.UnmarshalWithParams(m.Body.Bytes, &mb, typeMANB); err != nil {
		return fmt.Errorf("failed to ASN.1 parse Img4 manifest body: %v", err)
	}

	var mProps []manifestProperties
	if _, err := asn1.UnmarshalWithParams(mb[0].Properties.Bytes, &mProps, typeMANP); err != nil {
		return fmt.Errorf("failed to ASN.1 parse Img4 manifest properties: %v", err)
	}

	props, err := parseManifestProperties(mProps[0].Properties.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse Img4 manifest properties: %v", err)
	}

	result.Manifest = Manifest{
		Properties:   *props,
		ApImg4Ticket: i.Manifest,
		img4Manifest: m,
	}

	return nil
}

func parseRestoreInfo(i *img4, result *Img4) error {
	if i.RestoreInfo.Name == "" {
		return nil
	}

	gen, _, err := parseDataProp(i.RestoreInfo.Generator.Bytes, typeBNCN)
	if err != nil {
		return fmt.Errorf("failed to ASN.1 parse Generator: %v", err)
	}

	result.RestoreInfo = RestoreInfo{
		Generator:       *gen,
		img4RestoreInfo: i.RestoreInfo,
	}

	return nil
}

func OpenIm4p(path string) (*Im4p, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %v", path, err)
	}
	defer f.Close()
	return ParseIm4p(f)
}

func ParseIm4p(r io.Reader) (*Im4p, error) {
	data, err := readBuffer(r)
	if err != nil {
		return nil, err
	}

	var i Im4p
	if _, err := asn1.Unmarshal(data, &i.im4p); err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse Im4p: %v", err)
	}

	if i.im4p.KbagData != nil {
		if _, err := asn1.Unmarshal(i.im4p.KbagData, &i.Kbags); err != nil {
			return nil, fmt.Errorf("failed to ASN.1 parse Im4p KBAG: %v", err)
		}
	}

	return &i, nil
}

func OpenImg4(path string) (*img4, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %v", path, err)
	}
	defer f.Close()
	return ParseImg4(f)
}

func ParseImg4(r io.Reader) (*img4, error) {
	data, err := readBuffer(r)
	if err != nil {
		return nil, err
	}

	var i img4
	if _, err := asn1.Unmarshal(data, &i); err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse Img4: %v", err)
	}

	return &i, nil
}

// KeyBag Related Types
type im4pKBag struct {
	Name    string   `json:"name,omitempty"`
	Keybags []Keybag `json:"kbags,omitempty"`
}

type KeyBags struct {
	Type    string     `json:"type,omitempty"`
	Version string     `json:"version,omitempty"`
	Build   string     `json:"build,omitempty"`
	Devices []string   `json:"devices,omitempty"`
	Files   []im4pKBag `json:"files,omitempty"`
}

// MetaData contains minimal metadata needed for key bag parsing
type MetaData struct {
	Type                  string
	ProductVersion        string
	ProductBuildVersion   string
	SupportedProductTypes []string
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
	data, err := readBuffer(r)
	if err != nil {
		return "", err
	}

	var img4Test img4
	if _, err := asn1.Unmarshal(data, &img4Test); err == nil && img4Test.Name == "IMG4" {
		return "IMG4", nil
	}

	var im4pTest im4p
	if _, err := asn1.Unmarshal(data, &im4pTest); err == nil && im4pTest.Name == "IM4P" {
		return "IM4P", nil
	}

	return "", fmt.Errorf("unknown file type - not IMG4 or IM4P")
}

// SHSH Extraction Functions
// ExtractManifestFromShsh extracts IM4M manifest from SHSH blob with proper ASN.1 parsing
func ExtractManifestFromShsh(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read SHSH data: %v", err)
	}

	// Look for direct IM4M signature in the data
	im4mSig := []byte("IM4M")
	if idx := bytes.Index(data, im4mSig); idx != -1 {
		return extractManifestFromRawData(data, idx)
	}

	// Look for plist structure with ApImg4Ticket
	if bytes.Contains(data, []byte("ApImg4Ticket")) {
		return extractManifestFromPlistShsh(data)
	}

	return nil, fmt.Errorf("no recognizable IM4M manifest found in SHSH blob")
}

func extractManifestFromRawData(data []byte, startIdx int) ([]byte, error) {
	remainder := data[startIdx:]

	// Try to parse the ASN.1 structure to determine the correct length
	var manifest img4Manifest
	if _, err := asn1.Unmarshal(remainder, &manifest); err == nil {
		return manifest.Raw, nil
	}

	// Fallback to simple search approach
	manifestEnd := len(data)
	for i := startIdx + 4; i < len(data)-3; i++ {
		if bytes.Equal(data[i:i+4], []byte("IM4R")) ||
			bytes.Equal(data[i:i+4], []byte("IM4P")) {
			manifestEnd = i
			break
		}
	}

	if manifestEnd <= startIdx+4 {
		return nil, fmt.Errorf("invalid manifest structure in SHSH blob")
	}

	return data[startIdx:manifestEnd], nil
}

func extractManifestFromPlistShsh(data []byte) ([]byte, error) {
	var shsh struct {
		ApImg4Ticket []byte `plist:"ApImg4Ticket"`
		Generator    string `plist:"generator,omitempty"`
		BBTicket     []byte `plist:"BBTicket,omitempty"`
	}

	decoder := plist.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&shsh); err != nil {
		return nil, fmt.Errorf("failed to decode SHSH plist: %v", err)
	}

	if len(shsh.ApImg4Ticket) == 0 {
		return nil, fmt.Errorf("no ApImg4Ticket found in SHSH plist")
	}

	return shsh.ApImg4Ticket, nil
}

/* Validation Functions */

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

	if len(img.Manifest.Properties) == 0 {
		result.Warnings = append(result.Warnings, "No manifest properties found")
	} else {
		result.Components = append(result.Components, "manifest")
		validateCriticalProperties(img.Manifest.Properties, result)
	}
}

func validateCriticalProperties(props ManifestProperties, result *ValidationResult) {
	criticalProps := []string{"CHIP", "BORD"}
	for _, prop := range criticalProps {
		if _, exists := props[prop]; !exists {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Missing critical property: %s", prop))
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

/* Payload Processing Functions */

// DecryptPayload decrypts an IM4P payload using AES-CBC with provided IV and key
func DecryptPayload(path, output string, iv, key []byte) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("unable to open file %s: %v", path, err)
	}
	defer f.Close()

	i, err := ParseIm4p(f)
	if err != nil {
		return fmt.Errorf("unable to parse IM4P: %v", err)
	}

	if err := validateDecryptionInputs(i.Data, iv, key); err != nil {
		return err
	}

	decryptedData, err := decryptData(i.Data, iv, key)
	if err != nil {
		return err
	}

	return writeDecryptedOutput(decryptedData, output, path)
}

func validateDecryptionInputs(data, iv, key []byte) error {
	if len(data) < aes.BlockSize {
		return fmt.Errorf("IM4P data too short")
	}

	if len(data)%aes.BlockSize != 0 {
		return fmt.Errorf("IM4P data is not a multiple of the block size")
	}

	return nil
}

func decryptData(data, iv, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(data, data)
	return data, nil
}

func writeDecryptedOutput(data []byte, output, inputPath string) error {
	of, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %v", output, err)
	}
	defer of.Close()

	var r io.Reader

	// Check for LZFSE compression and decompress if needed
	if len(data) >= 4 && bytes.Equal(data[:4], []byte("bvx2")) {
		log.Debug("Detected LZFSE compression")
		decompressed := lzfse.DecodeBuffer(data)
		if len(decompressed) == 0 {
			return fmt.Errorf("failed to LZFSE decompress %s", inputPath)
		}
		r = bytes.NewReader(decompressed)
	} else {
		r = bytes.NewReader(data)
	}

	if _, err := io.Copy(of, r); err != nil {
		return fmt.Errorf("failed to write decrypted data to file %s: %v", output, err)
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

	payloadData, err := extractPayloadData(f, isImg4)
	if err != nil {
		return err
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

func extractPayloadData(f *os.File, isImg4 bool) ([]byte, error) {
	if isImg4 {
		i, err := ParseImg4(f)
		if err != nil {
			return nil, fmt.Errorf("failed to parse IMG4: %v", err)
		}
		return i.IM4P.Data, nil
	}

	i, err := ParseIm4p(f)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IM4P: %v", err)
	}
	return i.Data, nil
}
